using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ui.Data.Entities;

namespace Ui.Core.Repositories
{
    public interface ITokenGeneratorService
    {
        #region IMethods

        string GenerateToken(IdentityUser user, IList<string> userRoles);

        string GenerateRefreshToken();

        bool ValidateRefreshToken(string refreshToken);

        Task CreateRefreshToken(UserRefreshToken model);

        Task<UserRefreshToken> GetByRefreshToken(string refreshToken);

        Task DeleteRefreshToken(Guid id);
        Task<UserRefreshToken> GetByUserId(string userId);

        #endregion
    }
}
