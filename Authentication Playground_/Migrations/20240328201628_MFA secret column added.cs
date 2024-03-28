using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authentication_Playground_.Migrations
{
    /// <inheritdoc />
    public partial class MFAsecretcolumnadded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MFASecret",
                table: "Users",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MFASecret",
                table: "Users");
        }
    }
}
