using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CRUD_Angular_16.Data;

namespace CRUD_Angular_16.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        private readonly DataContext _context;

        public TestController(DataContext context)
        {
            _context = context;
        }

        // GET: api/test
        [HttpGet]
        public async Task<IActionResult> TestConnection()
        {
            try
            {
                // Verifica si la tabla 'Users' existe y si tiene datos.
                bool tableExists = await _context.Database.CanConnectAsync();

                if (!tableExists)
                {
                    return StatusCode(500, "No se pudo conectar a la base de datos.");
                }

                // Si la tabla 'Users' no existe, puedes crear una prueba de conexión más general
                var result = await _context.Users.FirstOrDefaultAsync();

                if (result == null)
                {
                    return Ok("Conexión exitosa pero sin datos en la tabla 'Users'.");
                }

                return Ok($"Conexión exitosa, primer usuario: {result.Username}");
            }
            catch (Exception ex)
            {
                // Si ocurre un error al intentar conectarse, devuelve un error detallado
                return StatusCode(500, $"Error al conectar con la base de datos: {ex.Message}");
            }
        }
    }
}
