using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using backend;
using backend.Models;

namespace backend.Controllers;

[ApiController]
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    private readonly AppDbContext _db;

    public OrdersController(AppDbContext db)
    {
        _db = db;
    }

    // GET /api/orders
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        // Wenn du Orders noch nicht in DB hast, kommt halt leeres Array zurück.
        var orders = await _db.Set<Order>().ToListAsync();
        return Ok(orders);
    }
}
