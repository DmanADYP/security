using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.DTO;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController: Controller
    {       
        public IAuthRepository _repo;

        public IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserForRegisterDTO user)
        {
            // validation
            user.Username = user.Username.ToLower();
           if(await _repo.UserExistsAsync(user.Username)){
              ModelState.AddModelError("Username", "Username already exists");
           } 

            if(!ModelState.IsValid){
                return BadRequest(ModelState);
            }
           

           var userToCreate = new User{
               UserName = user.Username
           };
           var createUser = await _repo.RegisterAsync(userToCreate, user.Password);

           return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserForLoginDTO userLogin){
            try{

            
            var userFromRepo = _repo.LoginAsync(userLogin.Username, userLogin.Password);

            if (userFromRepo == null){
                return Unauthorized();
            }
           
           //generate the token
           var tokenHandler = new JwtSecurityTokenHandler();
           var key = Encoding.ASCII.GetBytes(_config.GetSection("AppSettings:Token").Value);
           var tokenDescriptor = new SecurityTokenDescriptor 
           {
               Subject = new ClaimsIdentity(new Claim[]
               {
                   new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                   new Claim(ClaimTypes.Name, userLogin.Username)
               }),

               Expires = DateTime.UtcNow.AddDays(1),
               SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
           };

           var token = tokenHandler.CreateToken(tokenDescriptor);
           var tokenString = tokenHandler.WriteToken(token);

           return Ok(new {tokenString});
           } catch(Exception e){
            throw;    
        }
        }

    }
}