//! Running the receiver as a Windows service (`scopy service install|uninstall|run`).

use crate::logln;
use crate::server::{self, ServeOptions};
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType,
    ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "scopy";
const DISPLAY: &str = "StreamCopy receiver";

static OPTIONS: OnceLock<ServeOptions> = OnceLock::new();
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();

/// Installs and starts the service, which runs `scopy service run <args>` as LocalSystem.
pub fn install(serve_args: Vec<OsString>) -> Result<()> {
    let mut args: Vec<OsString> = vec!["service".into(), "run".into()];
    args.extend(serve_args);
    install_as(NAME, DISPLAY, "Receives and sends StreamCopy (scopy) jobs for local SMB shares.", args)
}

pub fn uninstall() -> Result<()> {
    uninstall_as(NAME)
}

/// Installs and starts a scopy service running `scopy.exe <args>` as LocalSystem, started automatically.
pub(crate) fn install_as(name: &str, display: &str, description: &str, args: Vec<OsString>) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .context("cannot open the service manager — run this from an elevated (admin) prompt")?;
    let exe = std::env::current_exe()?;
    let info = ServiceInfo {
        name: name.into(),
        display_name: display.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: args,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.set_description(description)?;
    service.start(&[] as &[&OsStr])?;
    println!("installed and started service '{name}'");
    Ok(())
}

pub(crate) fn uninstall_as(name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("cannot open the service manager — run this from an elevated (admin) prompt")?;
    let service = manager.open_service(name, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..50 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    service.delete()?;
    println!("removed service '{name}'");
    Ok(())
}

/// Entry point when started by the service manager.
pub fn run(options: ServeOptions, log: Option<PathBuf>) -> Result<()> {
    let log = log.unwrap_or_else(|| std::env::current_exe().unwrap_or_default().with_file_name("scopy-service.log"));
    crate::util::log_to_file(&log)?;
    let _ = OPTIONS.set(options);
    service_dispatcher::start(NAME, ffi_service_main).context("not started by the service manager (use `scopy serve` instead)")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        logln!("service failed: {e:#}");
        set_state(ServiceState::Stopped, 1);
    }
}

fn run_service() -> Result<()> {
    let handler = |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Answer the stop request first; exiting inside the handler makes the caller see a failure.
            logln!("service stopping");
            set_state(ServiceState::StopPending, 0);
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                set_state(ServiceState::Stopped, 0);
                std::process::exit(0);
            });
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(NAME, handler)?;
    let _ = STATUS.set(handle);
    set_state(ServiceState::Running, 0);
    server::serve(OPTIONS.get().context("missing options")?)
}

/// What the running service accepts besides stop and shutdown (the sync service: session changes).
static EXTRA_CONTROLS: OnceLock<ServiceControlAccept> = OnceLock::new();

pub(crate) fn set_status_handle(handle: ServiceStatusHandle, extra: ServiceControlAccept) {
    let _ = STATUS.set(handle);
    let _ = EXTRA_CONTROLS.set(extra);
}

pub(crate) fn set_state(state: ServiceState, code: u32) {
    if let Some(h) = STATUS.get() {
        let running = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | EXTRA_CONTROLS.get().copied().unwrap_or(ServiceControlAccept::empty());
        let _ = h.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running { running } else { ServiceControlAccept::empty() },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: if state == ServiceState::StopPending { Duration::from_secs(5) } else { Duration::default() },
            process_id: None,
        });
    }
}
