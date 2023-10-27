###########################################################################
# Copyright 2015, 2016, 2017, 2018, 2019 IoT.bzh
#
# author: Fulup Ar Foll <fulup@iot.bzh>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

set(CMAKE_INSTALL_SO_NO_EXE 0)

# Project Info
# ------------------
set(PROJECT_PRETTY_NAME "OCPP Extention for AFB-binder")
set(PROJECT_DESCRIPTION "Provide OCPP-1.6+2.0.1 websocket RPC")
set(PROJECT_URL "https://github.com/Tux-EVSE/afb-ocpp-ext")
set(PROJECT_ICON "icon.jpg")
set(PROJECT_AUTHOR "Iot-Team")
set(PROJECT_AUTHOR_MAIL "secretariat@iot.bzh")
set(PROJECT_LICENSE "Apache-2")
set(PROJECT_LANGUAGES,"C")
set(PROJECT_VERSION 1.0)

# Where are stored default templates files from submodule or subtree app-templates in your project tree
set(PROJECT_CMAKE_CONF_DIR "conf.d")

# Compilation Mode (DEBUG, RELEASE)
# ----------------------------------
set(BUILD_TYPE "DEBUG")

# Compiler selection if needed. Impose a minimal version.
# -----------------------------------------------
set (gcc_minimal_version 4.9)

# PKG_CONFIG required packages
# -----------------------------
set (PKG_REQUIRED_LIST
	libafb>=5
	libafb-binder>=5
)

# Print a helper message when every thing is finished
# ----------------------------------------------------
set( CLOSING_MESSAGE "Debug: afb-binder --name=ocpp-client --verbose --extension=package/lib/libafb-ocpp-ext.so --ocpp-client=csms-host:9310/ws/Tux-Basic --ocpp-pwd-base64=VHV4LUJhc2ljOnNub29weQ== #snoopy")

# (BUG!!!) as PKG_CONFIG_PATH does not work [should be an env variable]
# ---------------------------------------------------------------------
set(INSTALL_PREFIX $ENV{HOME}/usr/local)
set(CMAKE_PREFIX_PATH ${CMAKE_INSTALL_PREFIX}/lib64/pkgconfig ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig)
set(LD_LIBRARY_PATH ${CMAKE_INSTALL_PREFIX}/lib64 ${CMAKE_INSTALL_PREFIX}/lib)

# This include is mandatory and MUST happens at the end
# of this file, else you expose you to unexpected behavior
# -----------------------------------------------------------
include(CMakeAfbTemplates)
