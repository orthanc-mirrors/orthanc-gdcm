# Orthanc - A Lightweight, RESTful DICOM Store
# Copyright (C) 2012-2016 Sebastien Jodogne, Medical Physics
# Department, University Hospital of Liege, Belgium
# Copyright (C) 2017-2022 Osimis S.A., Belgium
# Copyright (C) 2021-2022 Sebastien Jodogne, ICTEAM UCLouvain, Belgium
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


if (STATIC_BUILD OR NOT USE_SYSTEM_GDCM)
  if (USE_LEGACY_GDCM)
    set(GDCM_URL "http://orthanc.osimis.io/ThirdPartyDownloads/gdcm-2.8.9.tar.gz")
    set(GDCM_MD5 "aeb00e0cb5375d454010a72e2e0f6154")
  else()
    set(GDCM_URL "http://orthanc.osimis.io/ThirdPartyDownloads/gdcm-3.0.10.tar.gz")
    set(GDCM_MD5 "28c70d02c2005a8c9d2a5847c8ba3c00")
  endif()
  
  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR
      ${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR
      ${CMAKE_SYSTEM_NAME} STREQUAL "kFreeBSD")
    # If using gcc, build GDCM with the "-fPIC" argument to allow its
    # embedding into the shared library containing the Orthanc plugin
    set(AdditionalCFlags "-fPIC")
    set(AdditionalCxxFlags ${AdditionalCFlags})
  elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Windows" AND
      CMAKE_COMPILER_IS_GNUCXX)
    # Prevents error: "jump to label ‘err’ crosses initialization" of some variable
    # within "Source/Common/gdcmCAPICryptographicMessageSyntax.cxx" if using MinGW
    set(AdditionalCxxFlags "-fpermissive")
  elseif (${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
    # This definition is necessary to compile
    # "Source/MediaStorageAndFileFormat/gdcmFileStreamer.cxx"
    set(AdditionalCFlags "-Doff64_t=off_t") 
    set(AdditionalCxxFlags ${AdditionalCFlags})
  endif()
  
  set(Flags
    "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} ${AdditionalCFlags}"
    "-DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} ${AdditionalCxxFlags}"
    -DCMAKE_C_FLAGS_DEBUG=${CMAKE_C_FLAGS_DEBUG}
    -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
    -DCMAKE_C_FLAGS_RELEASE=${CMAKE_C_FLAGS_RELEASE}
    -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
    -DCMAKE_C_FLAGS_MINSIZEREL=${CMAKE_C_FLAGS_MINSIZEREL}
    -DCMAKE_CXX_FLAGS_MINSIZEREL=${CMAKE_CXX_FLAGS_MINSIZEREL} 
    -DCMAKE_C_FLAGS_RELWITHDEBINFO=${CMAKE_C_FLAGS_RELWITHDEBINFO} 
    -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
    -DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}
    -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
    )

  if (CMAKE_TOOLCHAIN_FILE)
    # Take absolute path to the toolchain
    get_filename_component(TMP ${CMAKE_TOOLCHAIN_FILE} REALPATH BASE ${CMAKE_SOURCE_DIR})
    list(APPEND Flags -DCMAKE_TOOLCHAIN_FILE=${TMP})
  endif()

  # Don't build manpages (since gdcm 2.8.4)
  list(APPEND Flags -DGDCM_BUILD_DOCBOOK_MANPAGES=OFF)

  if ("${CMAKE_SYSTEM_VERSION}" STREQUAL "LinuxStandardBase")
    # Trick to disable the compilation of socket++ by gdcm, which is
    # incompatible with LSB, but fortunately only required for DICOM
    # Networking
    list(APPEND Flags -DGDCM_USE_SYSTEM_SOCKETXX=ON)

    # Detect the number of CPU cores to run "make" with as much
    # parallelism as possible
    include(ProcessorCount)
    ProcessorCount(N)
    if (NOT N EQUAL 0)
      set(MAKE_PARALLEL -j${N})
    endif()
      
    # For Linux Standard Base, avoid building incompatible target gdcmMEXD (*)
    set(BUILD_COMMAND BUILD_COMMAND
      ${CMAKE_MAKE_PROGRAM} ${MAKE_PARALLEL}
      gdcmMSFF gdcmcharls gdcmDICT gdcmDSED gdcmIOD gdcmjpeg8
      gdcmjpeg12 gdcmjpeg16 gdcmopenjp2 gdcmzlib gdcmCommon gdcmexpat gdcmuuid)
  endif()

  # if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  #   set(EXTRA_CMAKE_FLAGS -DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET} -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES})
  # else()
  #   set(EXTRA_CMAKE_FLAGS "")
  # endif()

  include(ExternalProject)
  externalproject_add(GDCM
    URL "${GDCM_URL}"
    URL_MD5 "${GDCM_MD5}"
    TIMEOUT 60
    CMAKE_ARGS -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} ${Flags}
    ${BUILD_COMMAND}    # Customize "make", only for Linux Standard Base (*)
    INSTALL_COMMAND ""  # Skip the install step
    )

  if(MSVC)
    set(Suffix ".lib")
    set(Prefix "")
  else()
    set(Suffix ".a")
    list(GET CMAKE_FIND_LIBRARY_PREFIXES 0 Prefix)
  endif()

  set(GDCM_LIBRARIES
    # WARNING: The order of the libraries below *is* important!
    ${Prefix}gdcmMSFF${Suffix}
    ${Prefix}gdcmcharls${Suffix}
    ${Prefix}gdcmDICT${Suffix}
    ${Prefix}gdcmDSED${Suffix}
    ${Prefix}gdcmIOD${Suffix}
    ${Prefix}gdcmjpeg8${Suffix}
    ${Prefix}gdcmjpeg12${Suffix}
    ${Prefix}gdcmjpeg16${Suffix}
    ${Prefix}gdcmopenjp2${Suffix}
    ${Prefix}gdcmzlib${Suffix}
    ${Prefix}gdcmCommon${Suffix}
    ${Prefix}gdcmexpat${Suffix}

    #${Prefix}socketxx${Suffix}
    #${Prefix}gdcmMEXD${Suffix}  # DICOM Networking, unneeded by Orthanc plugins
    #${Prefix}gdcmgetopt${Suffix}
    )

  if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    list(APPEND GDCM_LIBRARIES
      rpcrt4   # For UUID stuff
      )
  else()
    list(APPEND GDCM_LIBRARIES
      ${Prefix}gdcmuuid${Suffix}
      )
  endif()

  ExternalProject_Get_Property(GDCM binary_dir)
  include_directories(${binary_dir}/Source/Common)
  link_directories(${binary_dir}/bin)

  ExternalProject_Get_Property(GDCM source_dir)
  include_directories(
    ${source_dir}/Source/Common
    ${source_dir}/Source/DataDictionary
    ${source_dir}/Source/DataStructureAndEncodingDefinition
    ${source_dir}/Source/MediaStorageAndFileFormat
    )

else()
  find_package(GDCM REQUIRED)
  if (GDCM_FOUND)
    include(${GDCM_USE_FILE})
    set(GDCM_LIBRARIES gdcmCommon gdcmMSFF)
  else(GDCM_FOUND)
    message(FATAL_ERROR "Cannot find GDCM, did you set GDCM_DIR?")
  endif(GDCM_FOUND)
endif()
