from dataclasses import dataclass

@dataclass(frozen=True)
class HardeningProfile:
    name: str = "vulnhgnn-secure"
    optimization: str = "-O2"
    stack_protector: str = "-fstack-protector-all"
    fortify: str = "-D_FORTIFY_SOURCE=2"
    pie_compile: str = "-fPIE"
    pie_link: str = "-pie"
    relro: str = "-Wl,-z,relro"
    now: str = "-Wl,-z,now"
    noexecstack: str = "-Wl,-z,noexecstack"

    def compile_flags(self):
        return [self.optimization, self.stack_protector, self.fortify, self.pie_compile]

    def link_flags(self):
        return [self.pie_link, self.relro, self.now, self.noexecstack]
