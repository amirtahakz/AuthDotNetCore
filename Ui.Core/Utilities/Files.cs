using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace Ui.Core.Utilities
{
    public static class Files
    {
        #region Methods

        public static async Task<string> UploadFileAsync(this IFormFile inputTarget, string savePath)
        {
            if (inputTarget == null) return "File Not Found";
            var fileName = Guid.NewGuid() + inputTarget.FileName;


            var folderName = Path.Combine(Directory.GetCurrentDirectory(), savePath.Replace("/", "\\"));
            if (!Directory.Exists(folderName))
            {
                Directory.CreateDirectory(folderName);
            }
            var path = Path.Combine(folderName, fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                await inputTarget.CopyToAsync(stream);
            }
            return fileName;
        }
        public static string DownloadFile(Uri url, string savePath)
        {
            try
            {
                if (url == null || savePath == null) return "File Not Found";
                var Client = new WebClient();
                Client.DownloadFileAsync(url, savePath);
                return "Downloaded";
            }
            catch
            {

                throw new Exception("Somethinc is wrong");
            }
        }
        public static bool IsFile(this IFormFile file)
        {
            if (file == null) return false;
            var path = Path.GetExtension(file.FileName);
            path = path.ToLower();
            if (path == ".mp4" || path == ".mp3" || path == ".zip" ||
                path == ".rar" || path == ".wav" || path == ".docx" ||
                path == ".mmf" || path == ".m4a" || path == ".ogg" ||
                path == ".doc" || path == ".pdf" || path == ".txt" ||
                path == ".xls" || path == ".xla" || path == ".xlsx" ||
                path == ".ppt" || path == ".pptx" || path == ".gif" ||
                path == ".jpg" || path == ".png" || path == ".tif" || path == ".wmv" ||
                path == ".bmp" || path == ".wmf" || path == ".gif" || path == ".log")
            {
                return true;
            }
            return false;
        }
        public static bool IsVideo(this IFormFile file)
        {
            if (file == null) return false;
            var path = Path.GetExtension(file.FileName);
            path = path.ToLower();
            if (path == ".mp4")
            {
                return true;
            }
            return false;
        }
        public static bool IsImage(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return false;
            var path = Path.GetExtension(fileName);
            path = path.ToLower();
            if (path == ".jpg" || path == ".png" || path == ".bmp" || path == ".svg" || path == ".jpeg")
            {
                return true;
            }
            return false;
        }

        #endregion
    }
}