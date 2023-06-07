#!bin/bash

package_name="WFA-QuickTrack-ControlAppC"
version=""
git_revision=""
deb_name=${package_name}.deb
control_file=${package_name}/DEBIAN/control
postinst_file=${package_name}/DEBIAN/postinst
prerm_file=${package_name}/DEBIAN/prerm
postrm_file=${package_name}/DEBIAN/postrm
source_folder=${package_name}/usr/local/bin/${package_name}/source
installed_source_folder=/usr/local/bin/${package_name}/source

create_source_folder() {
    rm -rf ${package_name}
    mkdir -p ${package_name}/DEBIAN
    mkdir -p ${source_folder}
}

copy_filter_source() {
    cp -rf *.c *.h Makefile ${source_folder}
    cp -rf patch_nwmgr.sh ${source_folder}
    cp -rf QT_dhcpd.conf ${source_folder}
}

create_control() {
    echo "Package: ${package_name}" >"$control_file"
    echo "Version: ${version}-${revision}" >>"$control_file"
    echo "Architecture: all" >>"$control_file"
    echo "Depends: build-essential, arping, isc-dhcp-server, iw" >>"$control_file"
    echo "Essential: no" >>"$control_file"
    echo "Conflicts: wfa-indigo-controlappc" >>"$control_file"
    echo "Priority: optional" >>"$control_file"
    echo "Maintainer: Wi-Fi Alliance" >>"$control_file"
    echo "Description: This Software is to control the DUT and test platform" >>"$control_file"
    echo "" >>"$control_file"
}

create_postinst() {
    echo "#!/bin/bash" >"$postinst_file"
    echo "echo \"Start the installation and compile the source code.\"" >>"$postinst_file"
    echo "cd ${installed_source_folder}" >>"$postinst_file"
    echo "sed -i 's/VERSION = /VERSION = \"${version}\"#VERSION = /' Makefile" >>"$postinst_file"
    echo "make clean >/dev/null" >>"$postinst_file"
    echo "make >/dev/null" >>"$postinst_file"
    echo "cp app ../app_dut" >>"$postinst_file"
    echo "make clean >/dev/null" >>"$postinst_file"

    echo "sed -i 's/ROLE = dut/ROLE = tp/' Makefile" >>"$postinst_file"
    echo "make >/dev/null" >>"$postinst_file"
    echo "cp app ../app_tp" >>"$postinst_file"
    echo "make clean >/dev/null" >>"$postinst_file"

    echo "cp QT_dhcpd.conf ../QT_dhcpd.conf" >>"$postinst_file"

    echo "echo \"Test application version\"" >>"$postinst_file"
    echo "../app_dut -v" >>"$postinst_file"
    echo "../app_tp -v" >>"$postinst_file"
    echo "echo \"Complete the installation. If you would like to modify the source code for the platform-specific change, you can go to ${installed_source_folder}\"" >>"$postinst_file"
    echo "echo \"\"" >>"$postinst_file"
    echo "echo \"Start to patch NetworkManager to unmanage the wl* interface.\"" >>"$postinst_file"
    echo "/bin/bash ${installed_source_folder}/patch_nwmgr.sh bkup" >>"$postinst_file"
    chmod 755 "$postinst_file"
}

create_prerm() {
    echo "#!/bin/bash" >"$prerm_file"
    echo "sudo killall app_dut >/dev/null 2>/dev/null" >>"$prerm_file"
    echo "sudo killall app_tp >/dev/null 2>/dev/null" >>"$prerm_file"
    echo "sleep 3" >>"$prerm_file"

    echo "if [ -d \"/usr/local/bin/WFA-QuickTrack-ControlAppC/source\" ]" >>"$prerm_file"
    echo "then" >>"$prerm_file"
    echo "cd ${installed_source_folder}" >>"$prerm_file"
    echo "rm -rf /usr/local/bin/${package_name}/app_dut" >>"$prerm_file"
    echo "rm -rf /usr/local/bin/${package_name}/app_tp" >>"$prerm_file"
    echo "/bin/bash ${installed_source_folder}/patch_nwmgr.sh restore" >>"$prerm_file"
    echo "rm -rf /usr/local/bin/${package_name}/QT_dhcpd.conf" >>"$prerm_file"
    echo "fi" >>"$prerm_file"

    chmod 755 "$prerm_file"
}

create_deb() {
    dpkg -b ${package_name} >/dev/null
}

if [ -z "$1" ]
then
    echo "Please specify the version. E.g., 1.0.10"
    exit
else
    version="$1"
    revision=`git rev-parse --short HEAD`
fi
create_source_folder
create_control
copy_filter_source
create_postinst
create_prerm
create_deb

echo "Complete. Please reference to the following usage."
echo "1. Please remove the package by \"sudo apt remove wfa-quicktrack-controlappc\""
echo "2. Please install the package by \"sudo apt install ./WFA-QuickTrack-ControlAppC.deb\""
