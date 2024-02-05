using System.ComponentModel.DataAnnotations;

namespace Identity_II.Models;

public class loginUserTwoFactoery
{
    [Required]
    public string email {get;set;}
    public bool TowFactory {get;set;}
}