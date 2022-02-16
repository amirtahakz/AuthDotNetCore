using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.Repositories;

namespace Ui.Core.Services
{
    public class TokenGeneratorService : ITokenGeneratorService
    {

        #region Connections

        private IConfiguration _configuration;

        public TokenGeneratorService(IConfiguration config)
        {
            _configuration = config;
        }

        #endregion

        #region Methods

        public string GenerateToken(IdentityUser user, IList<string> userRoles)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:AccessTokenSecret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.Now.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"])),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:RefreshTokenSecret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.Now.AddMinutes(int.Parse(_configuration["Jwt:RefreshTokenExpirationMinutes"])),
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public bool ValidateRefreshToken(string refreshToken)
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:RefreshTokenSecret"])),
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ClockSkew = TimeSpan.Zero
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(refreshToken, validationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        //public Task CreateRefreshToken(RefreshToken refreshToken)
        //{
        //    refreshToken.Id = Guid.NewGuid();

        //    _refreshTokens.Add(refreshToken);

        //    return Task.CompletedTask;
        //}

        //public Task<RefreshToken> GetByRefreshToken(string refreshToken)
        //{
        //    var tt = _refreshTokens.Count();
        //    RefreshToken result = _refreshTokens.FirstOrDefault(r => r.ReToken == refreshToken);

        //    return Task.FromResult(result);
        //}

        //public Task DeleteRefreshToken(Guid id)
        //{
        //    _refreshTokens.RemoveAll(r => r.Id == id);

        //    return Task.CompletedTask;
        //}

        //public Task DeleteAllRefreshTokens(string userName)
        //{
        //    _refreshTokens.RemoveAll(r => r.UserName == userName);

        //    return Task.CompletedTask;
        //}

        #endregion
    }
}
