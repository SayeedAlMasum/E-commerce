//Program.cs
using E_commerce.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                       ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// This line registers the “developer exception page” for database errors (e.g. EF Core migrations).
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Configure Identity. We’ve set RequireConfirmedAccount = false so that new users can log in immediately.
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
        options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<ApplicationDbContext>();

// Add MVC controllers with views
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();   // Shows detailed EF migration errors in the browser during development
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// ?????????? IMPORTANT ??????????
// This line ensures that the Identity middleware can read/write the authentication cookie.
// It must come immediately after UseRouting() and before UseAuthorization().
app.UseAuthentication();

app.UseAuthorization();

// Default MVC route
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Map Razor Pages (so that /Identity/Account/Login, /Identity/Account/Register, etc. works)
app.MapRazorPages();

app.Run();
