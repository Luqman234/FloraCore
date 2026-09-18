# FloraCore Hardware

This directory is the home for FloraCore hardware documentation and future hardware revision work.

Planned structure:

```text
hardware/
├── bom/          bills of materials
├── schematics/   electrical diagrams and PCB/schematic sources
├── enclosure/    mechanical/enclosure design files
├── wiring/       connector and wiring references
└── testing/      calibration and hardware validation notes
```

## Contribution notes

Hardware changes should document voltage/current assumptions, connector choices, compatibility with existing firmware, and relevant safety constraints.

Do not commit private manufacturing credentials, supplier account information, or secrets here.
