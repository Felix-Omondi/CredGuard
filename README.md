# CredGuard
A library handling both password hashing and JWT management

## Installation
In order to use this library, you need to add a reference to the `CredGuard.dll` in your project. You can do this by adding the following XML snippet to your project file:
```xml
<ItemGroup>
    <Reference Include="CredGuard">
        <HintPath>.\dlls\CredGuard.dll</HintPath>
    </Reference>
</ItemGroup>
```

## Usage
### Password Hashing
To hash a password, you can use the `HashingService` class:
```csharp
HashingService.HashPassword("myPassword");
```

### Password Verification
To verify a password against a hashed password, you can use the `HashingService` class:
```csharp
HashingService.VerifyPassword("myPassword", "hashedPassword");
```

### JWT Management
To generate a JWT token, you can use the `TokenService` class:
```csharp
var tokenService = new TokenService(configuration);
var token = tokenService.GenerateToken("John Doe", "john.doe@example.com", "User");
var authResponse = new AuthResponse
{
    Message = "Token generated successfully.",
    Token = token
};

// In this example, the JWT token is returned in the `AuthResponse` object, which contains a message and the generated token.
```

In order to use the `TokenService`, you need to provide a configuration object that contains the JWT settings. 
```json
{
  "JwtSettings": {
    "Key": "your-secret-key",
    "Issuer": "your-issuer",
    "Audience": "your-audience",
    "ExpiryHours": 0.5
  }
}

// In this example, the `ExpiryHours` is set to 0.5, which means the token will expire in 30 minutes. You can adjust this value as needed.
```

In `Program.cs` or your startup file, you would typically configure the services like this:
```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddCredGuard(builder.Configuration);

builder.Services.AddDbContext<YourDbContext>(options => options.UseNpgsql(builder.Configuration.GetConnectionString("defaultConnection")));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapScalarApiReference();
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseRouting();

app.UseAuthorization();

app.MapControllers();

app.Run();
```