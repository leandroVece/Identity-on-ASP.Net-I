# ASP.Net Identity

En este pequeño tutorial vamos a ver como integrar Identity a nuestros proyectos ASP.Net. Para comenzar podemos preguntarnos ¿por que integar Identity a nuestros proyectos?

Integrar ASP.NET Identity en tus proyectos ofrece varias ventajas relacionadas con la gestión de usuarios y la seguridad. Esto puede simplificar significativamente la implementación de autenticación y autorización, proporcionando una solución robusta y segura que sigue las mejores prácticas de desarrollo web.

## Creacion del proyecto.

Como siempre vamos a crear un nuevo proyecto.

    dotnet new mvc

Despues de crear este nuevo proyecto al que pueden llamarlo como quieran, vamos a instalar las dependencias que vamos a usar.

    dotnet add package Microsoft.EntityFrameworkCore.Sqlite --version
    dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version
    dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version
    dotnet add package Microsoft.EntityFrameworkCore --version 

>Recordatorio: Cada uno puede colocar la version con la que esta trabajando, Anteriormente para estos tutoriales solo trabajaba con Net 6, despues de forzarme a formatear mi PC decici usar Net 7.

Despues de intalar estas dependecias, vamos a hacer lo mismo que hicimos en todos nuestros proyectos de EF. crear un DataContext y una cadena de coneccion.

**Path: ./Data/DataContext.cs**

    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;

    namespace Identity_II.Data;

    public class DataContext : IdentityDbContext
    {
        public DataContext(DbContextOptions<DataContext> options): base(options)
        { }
    }

Como pueden apreciar a simple vista este DataContext no ereda de **DbContext** como en los trabajos que estabamos acostumbrados a hacer. Esto no es mucho problema porque **IdentityDbContext** hereda de **DbContext** para mantener la familiaridad con los trabajos que estaba acostumbrado mientras nos permite trabajar con las entidadaes de Identity.

>Para la cadena de Coneccion es como ya estabamos acostumrbado, por lo que no lo mencionare, pero si todavia esta perdido siempre puede ir al archivo **appsettings.json**.

El paso siguiente como en todo nuestros proyecto sera ir a nuestro archivo **program.cs** para inicializar las configuraciones y poder realizar las migraciones que vienen por defecto con Identity.

**Path: ./Program.cs**

    using Identity_II.Data;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;

    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    builder.Services.AddControllersWithViews();

    //For EF
    builder.Services.AddSqlite<DataContext>(builder.Configuration.GetConnectionString("SQLite"));

    //For Identity
    builder.Services.AddIdentity<IdentityUser, IdentityRole>()
        .AddEntityFrameworkStores<DataContext>()
        .AddDefaultTokenProviders();

    //For Authentication

    builder.Services.AddAuthentication(op => {
        op.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        op.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        op.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    });


    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    app.Run();

Con esto listo ahora solo tenemos que crear las migraciones.

    dotnet ef migrations add AddIdentity
    dotnet ef database update

Con esto si entramos al archivo con SQLite veremos las entidades que fueron creadas.![iamgen](./Identity%20II/img/Id1.png)

Hasta ahora no hicimos nada nuevo, hemos estado trabajando como cuando integrabamos EF en nuestros proyectos. Esta es la ventaja de Identity que nos permite trabajar con algo que ya estabamos familiarizados.

Vamos ahora a intentar agregar algunas instancias a una de las tablas que viene con Identity por defecto, para ellos nos vamos a situar en el archivo DataContext.

**Path: ./Data/DataContext.cs**

    public class DataContext : IdentityDbContext
    {
        public DataContext(DbContextOptions<DataContext> options): base(options)
        { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }

        private static void SeedRoles(ModelBuilder builder){
            builder.Entity<IdentityRole>().HasData(
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName ="ADMIN"},
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName ="USER"},
                new IdentityRole() { Name = "HR", ConcurrencyStamp = "3", NormalizedName ="RRHH"}
            );
        }
    }

Con esto solo necesitaremos hacer las migraciones para ver los cambios en nuestra base de datos.
>Nota: Si por casualidad no les funciona, intenten que NormalizedName este todo con mayuscula. no se si es alguna acualizacion de net. 7 y queda pendiente la busqueda, pero si estas entidades no tiene NormalizedName con mayuscula completamente no me funcionaban.

## Registro de usuario.

Asp Identity ya cuenta con instancias para cargar datos, por lo que solo tenemos que hacer uso de ellas. Para ello vamos a crear un nuevo controlador para hacer un registro de Usuario.

**Path: ./Controller/AuthenticationController.CS**

    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthenticationController(
            UserManager<IdentityUser> userManager,RoleManager<IdentityRole> roleManager,IConfiguration configuration )
        {  
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;

        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser data, string role){

            //check User Exist
            var UserExist = await _userManager.FindByEmailAsync(data.Email);
            if (UserExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "Usuario ya existe"});   
            }

            //Add the User en the DB
            IdentityUser user = new IdentityUser(){
                    Email = data.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = data.Username            
                };
            var result = await _userManager.CreateAsync(user, data.Password);
             return result.Succeeded
            ? StatusCode(StatusCodes.Status201Created,
                new Response { Status = "Success", Message = "Usuario creado"})
            : (IActionResult)StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "Error al crear el usuario: " + string.Join(", ", result.Errors.Select(e => e.Description))});
            //Assing a role

        }
    }

De esta simple manera, confirmamos que el usuario no fue creado anteriormente, lo agregamos a la base de datos y le asignamos un rol.

Para estas alturas te habras dado cuenta que hay clases que estan faltando.

    public class RegisterUser
    {
        public string Username {get;set;}
        public string Email {get;set;}
        public string Password {get;set;}
    }

    public class Response
    {
        public string Status {get;set;}
        public string Message {get;set;}
    }

Estas simples clases serviran como punto de apollo para nuestra demostracion. Como no hemos creado una vista para probar si nuestro codigo funciona vamos a instalar swagger en nuestros proyecto.

    dotnet add package Swashbuckle.AspNetCore

**Path: ./Program.cs**

    using Microsoft.OpenApi.Models;

    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    builder.Services.AddControllersWithViews();

    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo { Title = "Nombre de tu API", Version = "v1" });
    });

    //For EF
    ...

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        
        app.UseExceptionHandler("/Home/Error");
        //The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }
    app.UseSwagger();
        app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Nombre de tu API V1");
            });

    ...

Despues de instalar la dependencia y podemos correr nuestro proyecto y agregar en nuestra url la siguiente cadena de texto "/swagger/index.html" Esto nos quedaria algo asi.![segunda imagen](./Identity%20II/img/id2.png)

>Cuando crees Identity ya exigira que: Las contraseñas deben tener al menos un carácter no alfanumérico. Las contraseñas deben tener al menos un dígito ('0'-'9'). Las contraseñas deben tener al menos una mayúscula ('A'-'Z'). Asi mismo la necesidad de un rol es obligartorio.

Para esta altura ya te habras dado cuenta que no aprendimos nada nuevo ecencialemnte, sino que usamos lo que ya sabiamos y obtuvimos conocimiento de nuevas entidades que no estan fisicamente, pero que estan integradas con Identity.

## Roles

Despues de la prueba de cargar el usuario vimos que la implementacion de un rol es algo estrictamente necesario (obligario). Este rol se lo debemos asignar al usuario de manera automatica cuando lo creemos y podemos modificarlo desde un usuario con privilegios de Administrador.

Ahora ¿por que usar roles? si ya tienes un tiempo trabajando te parecera que esta pregunta se responde sola. Despues de todo no podemos confiarle el poder de modificar a terceros a su antojo. Solo el administrador podria realizar tales modificaciones.

A travez de los roles deberiamos ser capaces de permitir el acceso o negarlos. Comencemos con agregar los roles, para ellos es una buena practica distinguir si tal rol existe o no. Expecialemente cuando no configuramos correctamente Identity uno podria crear uno podria escribir un rol que no existe y crear todavia el usuario como lo hicimos anteriormente que solo teniamos que llenar el campo obligatorio.

**Path: ./Controller/AuthenticationController.CS**

    [HttpPost]
    public async Task<IActionResult> Register([FromBody] RegisterUser data, string role){

        //check User Exist
        var UserExist = await _userManager.FindByEmailAsync(data.Email);
        if (UserExist != null)
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new Response { Status = "Error", Message = "Usuario ya existe"});   
        }

        //Add the User en the DB
        IdentityUser user = new IdentityUser(){
                Email = data.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = data.UserName            
            };
        if (await _roleManager.RoleExistsAsync(role))
        {
            var result = await _userManager.CreateAsync(user, data.Password);
            if (!result.Succeeded)
            { 
                return (IActionResult)StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Error al crear el usuario: " + string.Join(", ", result.Errors.Select(e => e.Description))});
            }else
            {
                //Assing a role
                await _userManager.AddToRoleAsync(user,role);
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "Usuario creado"});
            }
            
        }else
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "El rol no existe"});
        }
             
    }

Con esto podemos verificar que los usuarios que agreguemos estan presentes en nuestra base de datos, lo que va a exigir un poco mas en el poder de computo.
![imagen 3](./Identity%20II/img/Id3.png)![imagen 3](./Identity%20II/img/Id4.png)

Por ahora continuemos con mas conceptos antes de comenzar con ejemplos mas practicos.

## Coneccion correo electronico via SMTP

Aunque en las pruebas alguien podria usar un correo electronico flaso para ver si se cargan correctamente los Email. Esto en si no es una bunea practica. Si el usuario olvida su contraseña o es necesario comunicarse con ese usuario, el medio mas comun para dicha comunicacion es el correo proporcionado.

Entonces para mantener una buena practica es necesario mandar un correo de confirmacion a la direccion proporcinada por el usuario.

Para ellos comencemos una nuevo proyecto "Class library" y para los que se preguntan que son los Class Library estos son una forma eficaz de organizar y distribuir código en aplicaciones .NET, permitiendo la reutilización, abstracción y mantenimiento más sencillo de tu código.

Para crearlo en la terminal vamos a escribir el siguiente comando. En nuestros caso vamos a llamarlos "User.Management.Services"

    dotnet new classlib -n NombreDeLaLibreria

>Nota: Para evitar confusiones crealo en la misma carpeta donde create el proyecto y no dentro del proyecto.

Volvamos ahora a nuestro proyecto y agreguemos una nueva configuracion en nuestro archivo appsettings.

**Path: ./appsettings.json**

    {
        ...
        "EmailConfigurations": {
            "From": "loelvece@gmail.com",
            "SmtpServer": "smtp.gmail.com",
            "Port": "465",
            "Username": "EmailEJEMPLO@gmail.com",
            "Password": "xxxx xxxx xxxx xxxx"
        }
    }

Para los valores el ejemplo muestra lo que se necesita. Sin embargo creo bueno recordar que lo mejor es concectarse a un correo nuevo o a uno temporal. En este ejemplo vamos a usar el correo Gmial.

Mia segundo recordatorio es que este no es la contraseña de la cuenta sino la que obtenemos cuando permitimos que Gmail pueda ser accedidos por aplicaciones de tercero. Para obtenenla seguimos los siguientes pasos.

>Recordatorio: Para este paso necesitas tener la verigicacion de 2 pasos acivada.
![imagen 5](./Identity%20II/img/Id5.png)
![imagen 6](./Identity%20II/img/Id6.png)

Cuando termines de verificar busca la opcion de  "Contraseñas de aplicación" o "Aplicaciones que tienen acceso a tu cuenta". Te permitira agregar un acceso a una aplicacion de terceros.

![imagen 7](./Identity%20II/img/Id7.png)

Cuando pulces crear, te saldra una pantalla con un codio que copiaras y pegaras en la seccion de Contraseñas del archivo appsettings.json

Con todo configurado desde el exterior, ahora podemos descargar una dependecia nueva que sera un paquete administrativo de correos electronicos En el nuevo proyecto o solucion que creamos.

    dotnet add package NETCore.MailKit --version 2.1.0

En el nuevo proyecto vamos a crear las clases y servicios para consumir estas nuevas opciones.


**Path:./User.Management.Services/Models/EmailConfigurations.cs**

    namespace User.Management.Services;

    public class EmailConfigurations
    {
        public string From {get;set;}
        public string SmtpServer {get;set;}
        public int Port {get;set;}
        public string Username {get;set;}
        public string Password {get;set;}
    }

**Path:./User.Management.Services/Models/Message.cs**

    using System.Collections.Generic;
    using System.Linq;
    using MimeKit;
    namespace User.Management.Services;

    public class Message
    {
        public List<MailboxAddress> To {get;set;}
        public string Subject {get;set;}
        public string Content {get;set;}

        public Message(IEnumerable<string> to, string subject, string content){
            this.To = new List<MailboxAddress>();
            To.AddRange(to.Select(x => new MailboxAddress("email",x)));
            this.Subject = subject;
            this.Content = content;

        }
    }

El codigo en si, sigue siendo algo muy simple. En la primera solo tenemos unas variables que coinciden con las variables de entorno que colocamos en nuestro archivo appsetting. El segundo modelo es un modelo simple que cuenta con una lista de MailboxAddress una clase propia de **MimeKit** que se utiliza comúnmente al trabajar con mensajes de correo electrónico para especificar los destinatarios, remitentes y otros campos relacionados con las direcciones de correo electrónico.

Con los modelos listo solo necesitamos consumir los servicios.
**Path:./User.Management.Services/Servieces/IEmailServices.cs**

    namespace User.Management.Services;

    public interface IEmailServices{

        void SendMail(Message message);
    }

**Path:./User.Management.Services/Servieces/EmailServices.cs**

    using MailKit.Net.Smtp;
    using MimeKit;

    namespace User.Management.Services;

    public class EmailServices : IEmailServices
    {

        private readonly EmailConfigurations _emailConfig;

        public EmailServices(EmailConfigurations emailConfig){
            _emailConfig = emailConfig;
        } 

        public void SendMail(Message message){
            var EmailMessage = CreateEmailMessage(message);
            Send(EmailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message){

            var EmailMessage = new MimeMessage();
            EmailMessage.From.Add(new MailboxAddress("email",_emailConfig.From));
            EmailMessage.To.AddRange(message.To);
            EmailMessage.Subject = message.Subject;
            EmailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text){ Text = message.Content};

            return EmailMessage;
        }

        void Send(MimeMessage mailMessage){
            using var client = new SmtpClient();
            try
            {
                client.Connect(_emailConfig.SmtpServer, _emailConfig.Port, true);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailConfig.Username,_emailConfig.Password);

                client.Send(mailMessage);
            }
            catch (System.Exception)
            {
                
                throw;
            }
            finally{
                client.Disconnect(true);
                client.Dispose();
            }
        }    
    }

Seguramente en el momento de que entres en tu proyecto, si estas usando VSC te daras cuenta que solo uno de los proyectos tienen aceso al inteliSense, lo que es normal. Para que todos los proyectos que abras puedan usar el InteliSense tienes que crear una espacio de trabajo.

Eso es tan facil como entrar a la opcion "File" y ir a la opcion de "Save Wordspace as" y guardar en la carpta donde se encuentran ambos archivos. O si tienes la extencion de **C# Dev kit** bastaria con que borres el archivo **.sln** y remuevas el espacio de trabajo, luego cuando lo abras de nuevo te daras cuenta que tendrsa un nuevo archivo **.sln** creado por la extencion.

![iamgen 8](./Identity%20II/img/Id8.png)

Ahora que los archivos los 2 proyectos estan conectados entre si podrmos configurar el archivo program.cs

**Path:./Identity II/Program.cs**

    using Identity_II.Data;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using Microsoft.OpenApi.Models;
    using User.Management.Services;

    var builder = WebApplication.CreateBuilder(args);
    var emailConfig = builder.Configuration
            .GetSection("EmailConfigurations")
            .Get<EmailConfigurations>();

    // Add services to the container.
    builder.Services.AddControllersWithViews();

    // Learn more about configuring Swagger/OpenAPI 
    ...
    //For EF
    ...

    //For Identity
    ...

    //For Authentication

    ...

    //add Email Conf

    builder.Services.AddSingleton(emailConfig);
    builder.Services.AddScoped<IEmailServices,EmailServices>();

    ...

Con esto ya podemos probar su nuestro codigo funciona. Para ellos vamos al controlador que creamos y creemos un endpoind para verificar.

**Path: ./Identity/Controllers/AutenticationController.cs**


    public class AuthenticationController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailServices _emailServisces;
        
        public AuthenticationController(
            UserManager<IdentityUser> userManager,RoleManager<IdentityRole> roleManager,IEmailServices emailServisces )
        {  
            _userManager = userManager;
            _roleManager = roleManager;
            _emailServisces = emailServisces;

        }
    ...

        [HttpGet]
        public async Task<ActionResult> testEmail(){
            var message = new Message(new string[]{"loelvece@gmail.com"},"Test", "<h1>Testing...</h1>");
            _emailServisces.SendMail(message);
            return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon"});       
        }
    }

Despues de probarlo, si todo esta bien configurado y no hay errores (Como en mi caso que estuve media hora para darme cuenta que tenia un error tipografico) El correo deberia ser enviado al correo que le ingresemos en la clase Message. Con esto ahora podemos enviar una verificacion por correo Electronico.

## Verificacion por Email

Ahora que sabemos como enviar correos electronicos por Email, podemos usarlo para enviarnos token de autenticacion. De esa manera solo crear cuentas **validas** que sean verificadas por el usuario. Esto no solo da una capa extra de seguridad, sino que tambien evita que usuarios **poco serios** ocupen recuersos inecesariamente. Para esto primero vamos a volver a nuestro archivo Program y vamos a agregar la siguiente linea de codio.

**Path:./Identity II/Program.cs**

    //Add Config for requiere Email

    builder.Services.Configure<IdentityOptions>(
        opt => opt.SignIn.RequireConfirmedEmail = true
    );

Establecer RequireConfirmedEmail en true significa que se requerirá que los usuarios confirmen su dirección de correo electrónico antes de que se les permita iniciar sesión. Con esto solo tenemos que retocar un poco nuestro codigo para que este pueda enviarnos un correo de autenticacion de usuarios.

**Path: ./Identity/Controllers/AutenticationController.cs**

    [HttpPost]
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

Lo que hicimos aqui fue optimizar ligeramente el metodo de registro. Solo fue ligero por lo que se puede mejoara mas. Como podemos observar la generacion del token se las podemos deribar a Identity quien despues de verificar que nuestro Email existe, enviara un hipervinculo a nuestro Email para que nosotros confirmemos.
Aqui es donde entra en juego nuestro nuevo metodo llamado **ConfirmEmail** que se encargara de verificar que nuestro Email exista, lo cual En este caso puede ser inecesario porque ya estabamos haciendo antes, pero lo dejo asi por si alguien quiere en vez de confiormar el Email, confirmar otro parametro.
Si este existe nos devolvera un mensaje que nos pedira revisar nuestro correo y su vemos el correo, encontraremos el link con los datos para confirmar nuestro correo.
![](./Identity%20II/img/Id9.png)

Al entrar nos llevara a una nueva vista (que en este caso no creamos) que nos confirma que nuestro usuario a sido validado y si entramos en nuestra base de datos nos damos cuenta que el campo confirmacion de Email ahora es true o 1.

![](./Identity%20II/img/Id10.png)
![](./Identity%20II/img/Id11.png)

Este campo es importante, despues de todo un usuario que no esta validado no deberia de tener acceso a los campo de los usuarios validados como crear contenido, Editar y demas. Al menos que la aplicacion lo exija.

>Consejo: hay que tener en cuenta que el usuario se registra en la base de datos, independientemente si esta validado o no. Esto puede ocupar memeria de manera inecesaria por lo que es buena practica acosar a los clientes con terminar de verificar su cuenta o borrar los datos despues de un tiempo especificado.

## Autenticacion y autiruzacion con JWT

Anteriormente en uno de mis tutoriales hicimos uso de JWT para crear un token de autorizacion implementando clonando un repositorio que ya tenia todo lo que necesitabamos. Ahora vamos a intentar hacerlo nosotros mismo desde 0. Primero vamos a agregar en nuestro archivo appsettings una nueva configuracion

**Path:./Identity II/appsettings.json**

    "JWT":{
        "ValidAudience": "http://localhost:5218,https://localhost:7113,http://localhost:5218",
        "ValidIssuer": "http://localhost:5218,https://localhost:5218",
        "Secret": "EstaEsMiSuperLlavePrivadaQueNadiePuedeDecifrarQueTieneNumeritosMira12345"
    }

Esta configuración se utiliza para validar y firmar JWT en tu aplicación. Los valores de **ValidAudience** y **ValidIssuer** definen las restricciones sobre a quién está destinado y quién lo emitió, mientras que **Secret**, que ya la vimos anteriormente, es la clave privada utilizada para asegurar la integridad del token. Es importante mantener la seguridad de esta clave para garantizar la seguridad del sistema.

Ahora vamos a generar un token que se nos dara cada vez que nos loguemos, este token tendra una determinada duracion. **Para fines practicos vamos no vamos a separar la logica del controlador con la de generacion de token, pero puedes tomar el reto para tener un codigo mas ordenado y limpio.**

**Path: ./Identity/Controllers/AutenticationController.cs**

    [HttpPost]

    public async Task<IActionResult> Login([FromBody] LoginUser data){

         //check User Exist
        var UserExist = await _userManager.FindByNameAsync(data.UserName);

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

Primero vamos a agregar estos dos metodos nuevos a nuestro controlador. En el metodo Loguin lo primero que hacemos es confirmar que el usuario exista, si existe Identity tiene su propia funcion de reconocimiento de contraseña El cual recibira el usuario y la contraseña para verificar que los datos concuerden.

Luego creamos una lista de reclamos. esto va a incluir informacion adicional sobre el usuario en forma de reclamos para que puda ser utilizada por la aplicacion que consume el token desde el lado del servidor.

- **new Claim(ClaimTypes.Name, UserExist.UserName!)**: Crea una nueva reclamación (Claim) que representa el nombre del usuario. Esta reclamación suele usarse para identificar al usuario autenticado.

- **new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())**: Crea una reclamación que utiliza el nombre registrado Jti (JWT ID). Esta reclamación proporciona un identificador único para el token JWT. En este caso, se está utilizando un nuevo **Guid** como valor para la reclamación Jti.

En algunos casos un usuario puede tener mas de un rol. por ejemplo en una aplicacion de comercio al mismo ususario se le puede asignar un rol de cliente, de empleado o administracion. Un cliente puede ser empleado y administrador y/o administrador de su propio emprendimiento. es por eso que agregamos los roles que tiene el usuario en un bucle que agregaremos a nuestra lista de reclamos.

Por ultimo nos tocaria hablar de la generacion de token. El metodo **GetToken** se encarga de crear y devolver un objeto JwtSecurityToken utilizando la información proporcionada, como las reclamaciones (claims), la clave secreta, la validez del emisor y la audiencia, y otros detalles necesarios para construir un token JWT (JSON Web Token).

**authSigningKey**: Se crea una instancia de SymmetricSecurityKey utilizando la clave secreta especificada en la configuración. Esta clave se utilizará para firmar y verificar la autenticidad del token.

**token**: Se crea un objeto JwtSecurityToken con los siguientes parámetros:
- issuer: El emisor del token, obtenido de la configuración.
- audience: La audiencia a la que está destinado el token, obtenido de la configuración.
- expires: La fecha y hora de expiración del token. En este caso, se establece para 3 horas después de la generación del token.
- claims: Las reclamaciones asociadas al usuario, que se pasan como parámetro al método. Estas reclamaciones pueden incluir detalles como el nombre del usuario, roles, etc.
- signingCredentials: Se utiliza para especificar la clave y el algoritmo de firma. En este caso, se utiliza HMAC-SHA256 como algoritmo de firma con la clave secreta obtenida de la configuración.

El resto del codigo se explica por si solo, pero si no aqui esta una foto con la respuesta. ![](./Identity%20II/img/Id12.png)

## Autenticación y autorización basadas en roles

Para esto ejemplo vamos a crear un nuevo controlador. Podemos llamarlo como queramos, en mi caso voy a llamarlo AdminCrontroller.
**Path: ./Identity/Controllers/AdminCrontroller.cs**

    public class AdminCrontroller : Controller
    {
        private readonly ILogger<AdminCrontroller> _logger;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminCrontroller(ILogger<AdminCrontroller> logger, RoleManager<IdentityRole> roleManager)
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

    }

En este metodo solo cree un nuevo metodo de contrololador que se encarga de traer una lista con los reles en nuestra base de datos. Ahora este controlador tiene la anotacion de autorizacion, por lo que si no estamos autorizados a entrar este nos devolvera un 401. Para ellos vamos a tener que autenticarnos.

Pero si lo probamos ahora este nos dara un error 500 y eso es porque nos falta una configuracion importante en nuestro archivo program.
**Path:./Identity II/Program.cs**

    //For Authentication

    builder.Services.AddAuthentication(op => {
    op.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    op.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    op.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(op => {
        op.SaveToken = true;
        op.RequireHttpsMetadata = false;
        op.TokenValidationParameters = new TokenValidationParameters(){
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
        };
    });

Con esto agregado a nuestro archivo podemos obtener el 401 que pertenece a la respuesta que el navegador nos devuelve al no estar autorizados. Seguramente les parece familiar, despues de todo son los mismos parametros que teniamos cuando generamos el Token.
Ahora ¿es necesario tenerlo asi? la respuesta es que no, podriamos crear un middlaware para tener mejor presentado el codigo, pero por el momento mantengamonos de esta manera.

Ahora bien, si entramos tenemos un segundo problema. ya obtuvimos la respuesta que buscabamos, pero ¿como puedo hacer con swagger para colocar el token que obtube despues de loguearme? vamos a tener que agregar algunas opciones quedando asi.
**Path:./Identity II/Program.cs**

    builder.Services.AddSwaggerGen(op =>
    {
        op.SwaggerDoc("v1", new OpenApiInfo { Title = "Nombre de tu API", Version = "v1" });
        op.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme{
            In = ParameterLocation.Header,
            Description = "Plase entre a valid token",
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            BearerFormat = "JWT",
            Scheme = "Bearer"
        });
        op.AddSecurityRequirement(new OpenApiSecurityRequirement {
            {
                new OpenApiSecurityScheme{
                    Reference = new OpenApiReference{
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                new string[]{}
            }
        });
    });

![](./Identity%20II/img/Id13.png)

>Nota: al llegar hasta aqui, me dio algunos problemas porque tenia errores de tipeo en el archivo appsettings, en especial con estas dos plaabras: **ValidAudience** y **ValidIssuer** por lo que si no sale del error 401 despues de implementar todo, les pido que revisen bien en todas partes donde esta puesto todo y que este todo como lo estoy poniendo. me paso que me olvide poner el **Type = SecuritySchemeType.Http** y no me autorizaba.

Ahora si a nuestros metodos le agregaramos algunas dataannotation a nuestros controlador, podremos agregar la condicionante para que aquellos usuarios que tengan administrador como rol puedan aceder de caso contrario devolvera un 403. 

    [Authorize(Roles ="Admin")]
    [ApiController]
    [Route("api/[controller]")]

Estas condiciones no solo se limitan asingnarle un rol, tambien podemos negar un solo rol de una manera similar.

    [Authorize(Roles !="User")]

## Aunteticacion de dos pasos

Como ya han visto hasta ahora, no casi no tocamos conocimientos nuevos. Simplemente aprendimos una forma ya estructurada de hacer algo que haciamos antes con Entity Framework. Siguiendo una serie de pasos e intrucciones Identity nos permite generar un robusto sistema de seguridad casi de manera instantanea.

En este caso no es diferente. si vamos a nuestra base de datos de Usuarios vemos que en unos de los campos de nuestra entidad usuario encontramos, Al igual que la de la confirmacion por Email, un campo llamado **TwoFactoryEnabled** un capo booleano que nos permitira distinguir si el usuario agrego la opcion de verificacion de 2 pasos o no.

>Nota: Tambien esta la posibilidad que por norma general la autenticacion de 2 pasos sea agregada automaticamente creado el usuario. Eso ya quedara en manos del desarrollador de la aplicacion.

Partiendo del punto de que nosotros permitamos al usuario elegir la verificacion de dos pasos, necesitamos proponer un orden logico. Primero se crea la cuenta, luego se loguea y en una seccion especifica de configuracion le damos la posibilidad de acceder a una verificacion de 2 pasos.

Para no Alargar esto vamos a usar el controlador que acabamos de crear para esa dicha configuracion. Este controlador ya cuenta con autenticacion requerida, por lo que es necesario que ingresemos en nuestra cuenta para obtener el loguin antes de poder hacer cualquier Cambio en nuestra configuracion.

**Path: ./Identity/Controllers/AdminCrontroller.cs**


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

Aqui simplemente hacemos un simple Update a los datos y cambiamos los valores de nuestra entidad. En este caso el campo **TwoFactoryEnabled** por medio de nuestro Email (aunque lo logico seria hacerlo por Id).

Luego de guardar los cambios vamos a hacer algunas modificaciones a nuestra funcion de Loguin.

**Path: ./Identity/Controllers/AutenticationController.cs**

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

Con este simple cambio agregamos el reconocimiento de sistema de autenticacion de dos pasos, Este enviara un Email por con un token de confirmacion el cual al recibirlo podremos ingresarlos para recibir el token de acceso. Para esto vamos a tener que agregar la clase de Identity llamada **SignInManager**

**Path: ./Identity/Controllers/AutenticationController.cs**

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
            return Ok();
        }
        ...
    }

Con este nueva clase y un nuevo metodo de acceso podemos ingresar el codigo que nos llego por el Email, Identity se encargara de los proceso de validacion por nosotros y podremos continuar normalemtne

![](./Identity%20II/img/Id14.png)

## Restrablecimiento de contraseña

Este es un tema un poco delicado, despues de todo la contraseña es la primer medida de seguridad para un usuario. De hay viene la importancia de que sea larga, variada y que se renueve con frecuencia.

Siempre nos vamos a encontrar con casos en los que nos olvidamos de nuestra contraseñas y como nuestros datos son encriptados no es posible recuperar la contraseña mirando la base de datos. Es pos eso que usamos datos personales del ususario para confirmar que son ellos al momento de restablecer una contraseña. Claro que esto no es para nada seguro.

¿Cual seria la solucion entonces? La solucion seria enviar a nuestro correo un token de acceso que le permitiera a los usuarios cambiar la contraseña. Este token, tendria una vida util limitada para evitar que ocupe memoria inecesariamente y para eviar darles tiempo a las personas mal intencionadas acceder a el.

Para ello lo primero que vamos a hacer es agregar una nueva configuracion para el tiempo de vida del token en nuestros archivo program.cs
**Path:./Identity II/Program.cs**

    //Add Config for requiere Email

    builder.Services.Configure<DataProtectionTokenProviderOptions>(op => op.TokenLifespan = TimeSpan.FromHours(10));

**Path: ./Identity/Controllers/AutenticationController.cs**

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

Para la logica de restablecer contraseña no es muy diferente a lo que ya hemos visto, simplemente un controlador que recibira un nuevo objeto que tendra los datos necesarios para restablecer la contraseña.

**Path:./Identity II/Models/SingUp/PaswordReset.cs**

    public class PaswordReset
    {

        public string Password {get;set;}
        public string ResetPasword {get;set;}
        public string Token {get;set;}
        public string Email {get;set;}

    }

Aqui vamos a terminar la primera parte de este tutorial. En la segunda parte vamos a refactorizar nuestro codigo para hacer uso de las buenas practicaas y ver algunas cosas mas sobre Identity.