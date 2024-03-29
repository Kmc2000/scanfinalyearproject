﻿// <auto-generated />
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using ProjectScan.Services;

#nullable disable

namespace ProjectScan.Migrations
{
    [DbContext(typeof(MalwareScannerContext))]
    [Migration("20230216145624_AddYaraTable")]
    partial class AddYaraTable
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "7.0.3");

            modelBuilder.Entity("ProjectScan.Models.KnownMalwareHash", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("Categorisation")
                        .HasColumnType("INTEGER");

                    b.Property<byte[]>("MalwareHash")
                        .HasColumnType("BLOB");

                    b.HasKey("Id");

                    b.ToTable("KnownBadHashes");
                });

            modelBuilder.Entity("ProjectScan.Models.YaraRuleset", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("Categorisation")
                        .HasColumnType("INTEGER");

                    b.Property<string>("YaraRule")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("KnownBadYaraRules");
                });
#pragma warning restore 612, 618
        }
    }
}
