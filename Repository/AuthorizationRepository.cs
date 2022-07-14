using AuthorizationMicroservice.Database;
using AuthorizationMicroservice.Database.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace AuthorizationMicroservice.Repository
{
    public class AuthorizationRepository : IAuthorizationRepository
    {
        public IConfiguration _configuration;
        public readonly DatabaseContext _context;

        public AuthorizationRepository(IConfiguration configuration, DatabaseContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        public string GenerateToken(UserCredential user)
        {
            try
            {
                if (_context.UserCredentials.Count()==0)
                {
                    UserCredential adminuser=new UserCredential() { Username="admin",Password="admin"};
                    _context.UserCredentials.Add(adminuser);
                    _context.SaveChanges();
                }
                
                if (!_context.UserCredentials.Any(u => u.Username == user.Username && u.Password == user.Password))
                {
                    return null;
                }
                
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, user.Username.ToString())
                    }),
                    Expires = DateTime.Now.AddMinutes(15),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                
                return tokenHandler.WriteToken(token);
            }
            catch (Exception exception)
            {
                return null;
            }
        }
    }
}
