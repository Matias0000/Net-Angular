using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CRUD_Angular_16.Data;
using CRUD_Angular_16.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging;

namespace CRUD_Angular_16.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly DataContext _context;  
        private readonly ILogger<AuthController> _logger; 

        public AuthController(IConfiguration configuration, DataContext context, ILogger<AuthController> logger)
        {
            _configuration = configuration;
            _context = context;
            _logger = logger; 
        }

   
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {

            _logger.LogInformation("Intentando iniciar sesión con el nombre de usuario: {Username}", model.Username);

            var user = await _context.Users
                                      .FirstOrDefaultAsync(u => u.Username == model.Username);

            if (user == null)
            {
                _logger.LogWarning("Usuario no encontrado: {Username}", model.Username);
                return Unauthorized("Invalid credentials");
            }

            _logger.LogInformation("Usuario encontrado: {Username}", model.Username);


            if (user == null)
                return Unauthorized("Invalid credentials");

            // Verificar la contraseña (comparando el hash)

            if (!VerifyPassword(model.Password, user.PasswordHash))
            {
                _logger.LogWarning("Contraseña incorrecta para el usuario: {Username}", model.Username);
                return Unauthorized("Invalid credentials");
            }

            _logger.LogInformation("Contraseña verificada para el usuario: {Username}", model.Username);

            if (VerifyPassword(model.Password, user.PasswordHash))
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Role, user.Role ?? "User")  
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(
                    _configuration["Jwt:Issuer"],
                    _configuration["Jwt:Audience"],
                    claims,
                    expires: DateTime.Now.AddHours(1),
                    signingCredentials: creds
                );

                _logger.LogInformation("JWT generado para el usuario: {Username}", user.Username);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }

            return Unauthorized("Invalid credentials");
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {

            var existingUser = await _context.Users
                                             .FirstOrDefaultAsync(u => u.Username == model.Username);
            if (existingUser != null)
                return BadRequest("Username is already taken");

            // Crear el hash de la contraseña
            var passwordHash = HashPassword(model.Password);

            var user = new User
            {
                Username = model.Username,
                Email = model.Email,
                PasswordHash = passwordHash,
                Role = "User" 
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(new { message = "User registered successfully" });
        }


        private string HashPassword(string password)
        {
            var salt = new byte[16];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return $"{Convert.ToBase64String(salt)}:{hashed}";
        }

 
        private bool VerifyPassword(string password, string storedPasswordHash)
        {
            var parts = storedPasswordHash.Split(':');
            if (parts.Length != 2) return false;

            var salt = Convert.FromBase64String(parts[0]);
            var storedHash = parts[1];

            var computedHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return storedHash == computedHash;
        }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class RegisterModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
