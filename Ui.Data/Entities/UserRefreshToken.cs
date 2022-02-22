using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Data.Entities
{
    public class UserRefreshToken : BaseEntity
    {
        #region Properties

        public string UserId { get; set; }
        public string RefreshToken { get; set; }

        #endregion

        #region Relations

        #endregion
    }
}
