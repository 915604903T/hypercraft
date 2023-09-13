mod definitions;
mod detect;
mod percpu;
mod region;
mod vcpu;
mod vmcs;

pub use detect::has_hardware_support;
pub use percpu::VmxPerCpuState;
pub use vcpu::VmxVcpu;
