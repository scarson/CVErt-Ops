// .NET fixture for the performance-audit evals: an ASP.NET Core + EF Core controller
// exercising the core .NET lanes + the aspnet-core and sql-server-data modules +
// Variant notes. Illustrative (not built). See expected-findings.md (do NOT read it
// as the agent under test).

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("orders")]
public class OrdersController : ControllerBase
{
    private readonly ShopContext _db;
    public OrdersController(ShopContext db) => _db = db;

    [HttpGet("summary")]
    public async Task<IActionResult> Summary()
    {
        // PLANTED #1 (data-access / sql-server-data): EF N+1 — the related Customer is
        // accessed per row inside the loop without an Include/projection, firing one
        // query per order.
        var orders = await _db.Orders.Where(o => o.Status == "paid").ToListAsync();
        var lines = new List<string>();
        foreach (var o in orders)
        {
            var name = o.Customer.Name;     // lazy nav → one SELECT per order (N+1)
            // PLANTED #2 (memory/algorithmic): string built with += in a loop → O(n^2)
            // allocation; use a StringBuilder.
            string line = "";
            line += o.Id + ",";
            line += name + ",";
            line += o.TotalCents;
            lines.Add(line);
        }
        return Ok(lines);
    }

    [HttpGet("report")]
    public IActionResult Report()
    {
        // PLANTED #3 (data-access / sql-server-data): client-side evaluation — the whole
        // table is materialized with ToList() and THEN filtered/projected in memory,
        // instead of pushing the Where/Select to SQL. Also fetches all columns.
        var all = _db.Orders.ToList();
        var paid = all.Where(o => o.TotalCents > 0)
                       .Select(o => new { o.Id, o.TotalCents })
                       .ToList();

        // PLANTED #4 (concurrency / Variant notes): sync-over-async blocks a thread-pool
        // thread and can deadlock under the legacy sync context; await it instead.
        var count = _db.Orders.CountAsync().Result;

        return Ok(new { paid, count });
    }

    // BEYOND-THE-PACK (floor-not-ceiling): exceptions used for control flow INSIDE a
    // per-item loop. Throwing/catching is expensive in .NET (stack capture); on a hot
    // path this dominates. Validate with TryParse / a guard instead. NO .NET-pack
    // bullet names exception-as-control-flow cost — the agent must reason it.
    public int SumValidQuantities(IEnumerable<string> raw)
    {
        int sum = 0;
        foreach (var s in raw)
        {
            try { sum += int.Parse(s); }     // throws on every non-numeric item
            catch (FormatException) { /* skip */ }
        }
        return sum;
    }

    // DECOY (should NOT be flagged): a LINQ query over a fixed 3-element in-memory list,
    // built once. Mirrors the "materialize then filter" shape but n=3 and it's not on a
    // hot path. Flagging it ("push to SQL", "avoid ToList") is a precision/checklist
    // failure — there is no database and n is trivially bounded.
    private static readonly string[] Regions = { "us", "eu", "apac" };
    public bool RegionAllowed(string r) => Regions.Where(x => x == r).Any();
}
