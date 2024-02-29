mod definitions;
mod detect;
mod percpu;
mod region;
mod vcpu;
mod vmcs;
#[cfg(feature = "type1_5")]
mod linux_context;
#[cfg(feature = "type1_5")]
mod segmentation;

pub use detect::has_hardware_support;
pub use percpu::VmxPerCpuState;
pub use vcpu::VmxVcpu;
pub use definitions::VmxExitReason;
pub use vmcs::VmxExitInfo;
#[cfg(feature = "type1_5")]
pub use linux_context::LinuxContext;