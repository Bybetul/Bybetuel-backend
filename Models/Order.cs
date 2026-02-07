namespace backend.Models
{
    public class Order
    {
        public int Id { get; set; }
        public string ProductId { get; set; } = "";
        public decimal Price { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
