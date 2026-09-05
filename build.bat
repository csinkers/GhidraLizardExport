@echo off
::set GHIDRA_INSTALL_DIR=C:\Depot\bb\AlbionRE\ghidra_10.2.2_CUSTOM\
set GHIDRA_INSTALL_DIR=C:\Depot\TP\ghidra_12.2_DEV\
gradle -PGHIDRA_INSTALL_DIR=%GHIDRA_INSTALL_DIR% buildExtension

