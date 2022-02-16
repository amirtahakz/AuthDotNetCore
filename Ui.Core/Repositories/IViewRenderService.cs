using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Core.Repositories
{
    public interface IViewRenderService
    {
        #region IMethods

        Task<string> RenderToStringAsync(string viewName, object model);

        #endregion
    }
}
