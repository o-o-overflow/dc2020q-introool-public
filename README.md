# INTROOOL

## quick write up

- The trick: Data section that is not page aligned ends up mapped ALSO at the end of the executable page (that hosts the text section)
- Players-supplied data (the "ROP gadgets") are mapped twice in memory: in data section (r/w) and also in the code section.
- Instead of ROP gadgets, players can submit a shellcode, and use the patched nop sled to jump there, and get a shell
