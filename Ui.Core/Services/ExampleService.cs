using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.Repositories;
using Ui.Core.Utilities;
using Ui.Core.ViewModels;
using Ui.Data.Context;
using Ui.Data.Entities;

namespace Ui.Core.Services
{
    public class ExampleService : BaseService<Example>, IExampleService
    {
        #region Connections

        //services.AddScoped<IUserService, UserService>();
        public ExampleService(ApplicationDbContext context) : base(context) { }

        #endregion

        #region Methods



        #endregion
    }
}
