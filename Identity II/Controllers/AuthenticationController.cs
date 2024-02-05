
using Microsoft.AspNetCore.Mvc;
using Identity_II.Models;
using Microsoft.AspNetCore.Identity;
using User.Management.Services;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;


namespace Identity_II.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IEmailServices _emailServisces;
    private readonly IConfiguration _configuration;
    
    public AuthenticationController(
        UserManager<IdentityUser> userManager,RoleManager<IdentityRole> roleManager,IEmailServices emailServisces,
        SignInManager<IdentityUser> signInManager,IConfiguration configuration)
    {  
        _userManager = userManager;
        _roleManager = roleManager;
        _emailServisces = emailServisces;
        _configuration = configuration;
        _signInManager = signInManager;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginUser data){

         //check User Exist
        var UserExist = await _userManager.FindByNameAsync(data.UserName);

         //confirm Two Factory
        if (UserExist.TwoFactorEnabled)
        {
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(data.UserName,data.Password,false,true);

            var token = await _userManager.GenerateTwoFactorTokenAsync(UserExist,"Email");

            var message = new Message(new string [] {UserExist.Email!},"OPT Confirmations", token!);
                    _emailServisces.SendMail(message);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Enviado correo de confirmacion enviado exitosamente"});
        }

        if (UserExist != null && await _userManager.CheckPasswordAsync(UserExist,data.Password))
        {
            //claimlist creation
            var authClaims = new List<Claim>{
                new Claim(ClaimTypes.Name,UserExist.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //We add roles to the list
            var userRoles = await _userManager.GetRolesAsync(UserExist);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }
           
            //Generate the thoken the claims

            var jwt = GetToken(authClaims);
            return Ok( new {
                token = new JwtSecurityTokenHandler().WriteToken(jwt),
                expirations = jwt.ValidTo
            });
 
        }
        return Unauthorized();
    } 

    [HttpPost("login-2fa")]
    public async Task<IActionResult> Login2FA(string token, string username){
        var user = await _userManager.FindByNameAsync(username);
        var sign = await _signInManager.TwoFactorSignInAsync("Email",token, false, false);
        
        if (sign.Succeeded && user != null)
        {
             var authClaims = new List<Claim>{
                new Claim(ClaimTypes.Name,user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //We add roles to the list
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }
            //Generate the thoken the claims

            var jwt = GetToken(authClaims);
            return Ok( new {
                token = new JwtSecurityTokenHandler().WriteToken(jwt),
                expirations = jwt.ValidTo
            });
 
        }
        return Unauthorized();
    }

    private JwtSecurityToken GetToken(List<Claim> authClaims){
        var authSingingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSingingKey, SecurityAlgorithms.HmacSha256)
        );
        return token;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterUser data, string role){

        //check User Exist
        var UserExist = await _userManager.FindByEmailAsync(data.Email);
        if (UserExist != null)
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new Response { Status = "Error", Message = "Usuario ya existe"});   
        }
        if (!await _roleManager.RoleExistsAsync(role))
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "El rol no existe" });
        }

        //Add the User en the DB
        IdentityUser user = new IdentityUser(){
                Email = data.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = data.UserName            
            };
        
        var result = await _userManager.CreateAsync(user, data.Password);
        if (result.Succeeded)
        { 
            //Assing a role
            await _userManager.AddToRoleAsync(user,role);

            //Add token verify the email

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var confirmationLink = Url.Action(nameof(ConfirmEmail),"Authentication", new {token, email = user.Email});
            var confirmationLink = Url.ActionLink(nameof(ConfirmEmail),"Authentication", new {token, email = user.Email});
            
            
            var message = new Message(new string [] {user.Email!},"Confirmar Email por el link", confirmationLink!);
            _emailServisces.SendMail(message);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Usuario creado y correo de confirmacion enviado exitosamente"});
        }
        else{
            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "Error al crear el usuario: " + string.Join(", ", result.Errors.Select(e => e.Description))});
        }             
    }


    [HttpGet("ConfiorEmail")]
    public async Task<ActionResult> ConfirmEmail(string token, string email){

        var User = await _userManager.FindByEmailAsync(email);
        if (User != null)
        {
            var result = await _userManager.ConfirmEmailAsync(User,token);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon"});  
            }
        }
        return StatusCode(StatusCodes.Status500InternalServerError,
            new Response { Status = "Error", Message = "El usuario no Existe"});

    }

    [HttpPost("Forgot-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ForgoPassword([Required] string email){

        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var confirmationLink = Url.ActionLink(nameof(ResetPasword),"Authentication", new {token, email = user.Email});
            
            var message = new Message(new string [] {user.Email!},"Restablecer contraseña", confirmationLink!);
            _emailServisces.SendMail(message);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Por favor verifique su correo"});
        }

        return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "El correo no existe" });

    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ResetPasword(PaswordReset data){
        var user = await _userManager.FindByEmailAsync(data.Email);
        if (user != null)
        {
            var reset = await _userManager.ResetPasswordAsync(user, data.Token, data.Password);
            if (!reset.Succeeded)
            {
                foreach(var error in reset.Errors){
                    ModelState.AddModelError(error.Code,error.Description);
                }
                return Ok(ModelState);
            }
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon"});  
        }
        return StatusCode(StatusCodes.Status500InternalServerError,
            new Response { Status = "Error", Message = "El usuario no Existe"});

    }

    [HttpGet]
    public async Task<ActionResult> testEmail(){
        var message = new Message(new string[]{"loelvece@gmail.com"},"Test", "<h1>Testing...</h1>");
        _emailServisces.SendMail(message);
         return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon"});       
    }
}
