using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace ProjectScan.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Create hash table
            migrationBuilder.CreateTable(
                name: "KnownBadHashes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    MalwareHash = table.Column<byte[]>(type: "BLOB", nullable: true),
                    Categorisation = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KnownBadHashes", x => x.Id);
                });

            // Create YARA rule table
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
                name: "KnownBadHashes");

            migrationBuilder.DropTable(
                name: "KnownBadYaraRules");
        }
    }
}
