using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

[ApiController]
[Route("api/[controller]")]
public class RolesController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;

    public RolesController(RoleManager<IdentityRole> roleManager)
    {
        _roleManager = roleManager;
    }

    [HttpGet]
    public async Task<IActionResult> GetRoles()
    {
        // Obtener todos los roles
        var roles = await _roleManager.Roles.ToListAsync();

        // Puedes devolver la lista de roles directamente o adaptarla según tus necesidades
        return Ok(roles);
    }

     [HttpGet("RoleExists")]
    public async Task<IActionResult> GetRoleExists(string role)
    {
        // Verificar si el rol existe
        var roleExists = await _roleManager.RoleExistsAsync(role);

        // Puedes devolver el resultado directamente o adaptarlo según tus necesidades
        return Ok(roleExists);
    }

}