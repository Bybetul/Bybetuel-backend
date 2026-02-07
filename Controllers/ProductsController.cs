using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers
{
    [ApiController]
    [Route("api/products")]
    public class ProductsController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetProducts()
        {
            var products = new[]
            {
                new
                {
                    id = "p1",
                    name = "Bybetul Testprodukt",
                    price = 19.99,
                    active = true
                },
                new
                {
                    id = "p2",
                    name = "Bybetul Premium",
                    price = 29.99,
                    active = true
                }
            };

            return Ok(products);
        }
    }
}
