@echo off
::set GHIDRA_INSTALL_DIR=C:\Depot\bb\AlbionRE\ghidra_10.2.2_CUSTOM\
set GHIDRA_INSTALL_DIR=D:\Ghidra\ghidra_12.1.2_PUBLIC\
gradle -PGHIDRA_INSTALL_DIR=%GHIDRA_INSTALL_DIR% buildExtension

