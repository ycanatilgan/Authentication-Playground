using Authentication_Playground_.Data;
using Fido2NetLib;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<AppDbContext>(options 
    => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddSession();

#region FIDO2
var fido2Configuration = new Fido2Configuration
{
    ServerDomain = "localhost:44373",
    ServerName = "ycan in dev",
    Origin = "https://localhost:44373",
    TimestampDriftTolerance = 300000,
    MDSCacheDirPath = null // Set this property if needed
};

// Configure the Fido2Configuration service with a delegate that configures the provided instance
builder.Services.Configure<Fido2Configuration>(options =>
{
    options.ServerDomain = fido2Configuration.ServerDomain;
    options.ServerName = fido2Configuration.ServerName;
    options.Origin = fido2Configuration.Origin;
    options.TimestampDriftTolerance = fido2Configuration.TimestampDriftTolerance;
    options.MDSCacheDirPath = fido2Configuration.MDSCacheDirPath;
});

// Add the configuration as a singleton service
builder.Services.AddSingleton(fido2Configuration);
#endregion


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseSession();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
