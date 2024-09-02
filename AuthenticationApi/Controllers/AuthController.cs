
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationApi.Controllers;
// TODO => add error handling

public class AuthController : ControllerBase
{
    HttpClient http = new();
    public AuthController()
    {
        
    }
    
    // GET
    [AllowAnonymous]
    [HttpGet("auth")]
    public IActionResult Index()
    {
        return Ok("Hello world");
    }
    
    [Authorize]
    [HttpGet("more/treasure")]
    public IActionResult MoreTreasure()
    {
        return Ok("Found more treasure on linkedin island!");
    }
    [HttpPost("linkedin/callback")]
    public async Task<IActionResult> LinkedInCallback([FromBody] string authorizationCode)
    {
        //3-step process to login in with linkedin
        //1 create app on linkedin
        //2 acquire access code from linkedin for the user (done when frontend redirects)
        //3 exchange access code for a token and use the token to request user info from linkedin
        
        //here, we exchange the code for the token
        var token = await GetAccessToken(authorizationCode);
        if (token is null) return Unauthorized();

        //then use the token to grab user info from linkedin
        //var user = await GetUserInformation(token);
        //what to return here, probably some exception occured
        //not found may not be the appropriate response
        //if (user is null) return NotFound();

        //store in db if not exists or update the login counter

        //return the token for storage in the user browser,
        //returning the user info here directly is also an option 
        Console.WriteLine(token);
        return Ok(token);
        
        //or
        
        //return Ok((token, user));
        //return Ok(new { token = token, user = user });
    }

    private async Task<string?> GetAccessToken(string authorizationCode)
    {
        //url to request a new token
        var request = new HttpRequestMessage(HttpMethod.Post, "https://www.linkedin.com/oauth/v2/accessToken");
        
        //get secrets from configuration file
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", authorizationCode },
            { "redirect_uri", "http://localhost:5215" },
            { "client_id", "77tgedfsh93yy3" },
            { "client_secret", "1kUXuFiknbQrUEje" }
        });
        
        var response = await http.SendAsync(request);
        if (!response.IsSuccessStatusCode) return null;
         
        // the response is the token, assuming everything went well
        var content = await response.Content.ReadAsStringAsync();
        Console.WriteLine(content);

        return content;
    }

    private async Task<string?> GetUserInformation(string accessToken)
    {
        //grab the url from linkedin docs
        var request = new HttpRequestMessage(HttpMethod.Get,
            "https://api.linkedin.com/v2/userinfo");
        
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        
        var response = await http.SendAsync(request);
        if (!response.IsSuccessStatusCode) return null;
        
        var content = await response.Content.ReadAsStringAsync();
        return content;
        
    }
    
}