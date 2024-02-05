using System.ComponentModel.DataAnnotations;

namespace Identity_II.Models;

public class LoginUser
{
    [Required]
    public string UserName {get;set;}
    [Required]
    public string Password {get;set;}
}