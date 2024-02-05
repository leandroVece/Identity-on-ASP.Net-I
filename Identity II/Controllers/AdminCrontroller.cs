using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Identity_II.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Identity_II.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class AdminCrontroller : ControllerBase
{
    private readonly ILogger<AdminCrontroller> _logger;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AdminCrontroller(ILogger<AdminCrontroller> logger, RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    
    [HttpPost]
    public async Task<IActionResult> GetRoles()
    {
        // Obtener todos los roles
        var roles = await _roleManager.Roles.ToListAsync();

        // Puedes devolver la lista de roles directamente o adaptarla según tus necesidades
        return Ok(roles);
    }

    [HttpPost("settings")]
    public async Task<IActionResult> TowFactory([FromBody] loginUserTwoFactoery data){

         //check User Exist
        var UserExist = await _userManager.FindByEmailAsync(data.email);

        if (UserExist != null)
        {
            UserExist.TwoFactorEnabled = data.TowFactory;

             var result = await _userManager.UpdateAsync(UserExist);
             if (result.Succeeded)
             {
                 return StatusCode(StatusCodes.Status200OK,
                 new Response { Status = "Success", Message = "Cambios guardados correctamente"});
             }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "Error al guardar cambios"}); 
            }
        }
        return Unauthorized();
    } 

}
