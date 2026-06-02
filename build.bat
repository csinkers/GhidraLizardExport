@echo off
set GHIDRA_INSTALL_DIR=C:\Depot\bb\AlbionRE\ghidra_10.2.2_CUSTOM\
gradle -PGHIDRA_INSTALL_DIR=%GHIDRA_INSTALL_DIR% buildExtension
