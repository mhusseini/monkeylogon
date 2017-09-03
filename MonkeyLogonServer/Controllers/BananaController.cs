using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MonkeyLogon.Controllers
{
    [Produces("application/json")]
    [Route("api/Banana")]
    public class BananaController : Controller
    {
        [Authorize]
        [HttpGet]
        public IActionResult Get()
        {
            return this.Json(new[]
            {
                "Banana",
                "Banana",
                "Banana",
                "Banana"
            });
        }
    }
}