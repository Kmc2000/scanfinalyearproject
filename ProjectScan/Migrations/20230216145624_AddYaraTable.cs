using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ProjectScan.Migrations
{
    /// <inheritdoc />
    public partial class AddYaraTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "KnownBadYaraRules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    YaraRule = table.Column<string>(type: "TEXT", nullable: true),
                    Categorisation = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KnownBadYaraRules", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "KnownBadYaraRules");
        }
    }
}
