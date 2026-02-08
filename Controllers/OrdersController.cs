using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using backend.Models;

namespace backend.Controllers
{
    [ApiController]
    [Route("api/orders")]
    [Authorize] // <- wenn du es öffentlich willst, entferne diese Zeile
    public class OrdersController : ControllerBase
    {
        private readonly AppDbContext _db;

        public OrdersController(AppDbContext db)
        {
            _db = db;
        }

        // DTO für Create
        public record CreateOrderDto(string ProductId, decimal Price);

        // GET /api/orders
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var orders = await _db.Set<Order>()
                .AsNoTracking()
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();

            return Ok(orders);
        }

        // GET /api/orders/{id}
        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetById([FromRoute] int id)
        {
            var order = await _db.Set<Order>()
                .AsNoTracking()
                .FirstOrDefaultAsync(o => o.Id == id);

            if (order == null) return NotFound(new { message = "Order not found" });

            return Ok(order);
        }

        // POST /api/orders
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateOrderDto dto)
        {
            if (dto == null) return BadRequest(new { message = "Body missing" });

            var productId = (dto.ProductId ?? "").Trim();
            if (string.IsNullOrWhiteSpace(productId))
                return BadRequest(new { message = "ProductId is required" });

            if (dto.Price <= 0)
                return BadRequest(new { message = "Price must be > 0" });

            var order = new Order
            {
                ProductId = productId,
                Price = dto.Price,
                CreatedAt = DateTime.UtcNow
            };

            _db.Set<Order>().Add(order);
            await _db.SaveChangesAsync();

            return CreatedAtAction(nameof(GetById), new { id = order.Id }, order);
        }
    }
}
