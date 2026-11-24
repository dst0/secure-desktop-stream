# Injected with -DCMAKE_PROJECT_INCLUDE=/opt/sds/qt-host-moc.cmake (runs after every project()).
# The MSYS2 qt6-static package only ships Windows tool executables (moc.exe), which cannot run on
# the Linux build host. At the end of each project directory, point every AUTOMOC target at the
# Linux moc from Ubuntu's qt6-base-dev-tools instead (Sunshine itself only needs this for the tray
# library's QtTrayMenu.h). Host moc 6.10 and target Qt 6.12 share moc output revision 69.
set(SDS_HOST_MOC "/usr/lib/qt6/libexec/moc" CACHE FILEPATH "Linux moc used for AUTOMOC when cross-compiling")

if(NOT COMMAND _sds_use_host_moc)
    function(_sds_use_host_moc)
        get_property(_sds_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
        foreach(_sds_target IN LISTS _sds_targets)
            get_target_property(_sds_automoc "${_sds_target}" AUTOMOC)
            if(_sds_automoc)
                set_property(TARGET "${_sds_target}" PROPERTY AUTOMOC_EXECUTABLE "${SDS_HOST_MOC}")
            endif()
        endforeach()
    endfunction()
endif()

cmake_language(DEFER CALL _sds_use_host_moc)
