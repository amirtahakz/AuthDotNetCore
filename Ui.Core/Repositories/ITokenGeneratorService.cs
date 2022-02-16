using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.Models;

namespace Ui.Core.Repositories
{
    public interface ITokenGeneratorService
    {
        #region IMethods

        string GenerateToken(IdentityUser user, IList<string> userRoles);

        string GenerateRefreshToken();

        bool ValidateRefreshToken(string refreshToken);

        //Task CreateRefreshToken(RefreshToken model);
        //Task<RefreshToken> GetByRefreshToken(string refreshToken);

        //Task DeleteRefreshToken(Guid id);

        //Task DeleteAllRefreshTokens(string userName);

        #endregion
    }
}
