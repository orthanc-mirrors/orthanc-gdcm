/**
 * Orthanc - A Lightweight, RESTful DICOM Store
 * Copyright (C) 2012-2016 Sebastien Jodogne, Medical Physics
 * Department, University Hospital of Liege, Belgium
 * Copyright (C) 2017-2023 Osimis S.A., Belgium
 * Copyright (C) 2024-2024 Orthanc Team SRL, Belgium
 * Copyright (C) 2021-2024 Sebastien Jodogne, ICTEAM UCLouvain, Belgium
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **/


#pragma once

#include "GdcmImageDecoder.h"

#include "../Resources/Orthanc/Plugins/OrthancPluginCppWrapper.h"

#include <Compatibility.h>

#include <boost/thread.hpp>


namespace OrthancPlugins
{
  class GdcmDecoderCache : public boost::noncopyable
  {
  private:
    boost::mutex   mutex_;
    std::unique_ptr<OrthancPlugins::GdcmImageDecoder>  decoder_;
    size_t       size_;
    std::string  md5_;

    static std::string ComputeMd5(const void* dicom,
                                  size_t size);

  public:
    GdcmDecoderCache() : size_(0)
    {
    }

    OrthancImage* Decode(const void* dicom,
                         const uint32_t size,
                         uint32_t frameIndex);
  };
}
