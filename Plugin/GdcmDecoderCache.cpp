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


#include "GdcmDecoderCache.h"

#include <Compatibility.h>

namespace OrthancPlugins
{
  std::string GdcmDecoderCache::ComputeMd5(const void* dicom,
                                           size_t size)
  {
    std::string result;

    char* md5 = OrthancPluginComputeMd5(OrthancPlugins::GetGlobalContext(), dicom, size);

    if (md5 == NULL)
    {
      throw std::runtime_error("Cannot compute MD5 hash");
    }

    bool ok = false;
    try
    {
      result.assign(md5);
      ok = true;
    }
    catch (...)
    {
    }

    OrthancPluginFreeString(OrthancPlugins::GetGlobalContext(), md5);

    if (!ok)
    {
      throw std::runtime_error("Not enough memory");
    }
    else
    {    
      return result;
    }
  }


  OrthancImage* GdcmDecoderCache::Decode(const void* dicom,
                                         const uint32_t size,
                                         uint32_t frameIndex)
  {
    std::string md5 = ComputeMd5(dicom, size);

    // First check whether the previously decoded image is the same
    // as this one
    {
      boost::mutex::scoped_lock lock(mutex_);

      if (decoder_.get() != NULL &&
          size_ == size &&
          md5_ == md5)
      {
        // This is the same image: Reuse the previous decoding
        return new OrthancImage(decoder_->Decode(frameIndex));
      }
    }

    // This is not the same image
    std::unique_ptr<GdcmImageDecoder> decoder(new GdcmImageDecoder(dicom, size));
    std::unique_ptr<OrthancImage> image(new OrthancImage(decoder->Decode(frameIndex)));

    {
      // Cache the newly created decoder for further use
      boost::mutex::scoped_lock lock(mutex_);
      decoder_.reset(decoder.release());
      size_ = size;
      md5_ = md5;
    }

    return image.release();
  }
}
