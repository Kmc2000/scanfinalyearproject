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
    [Migration("20230121141403_InitialCreate")]
    partial class InitialCreate
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "7.0.2");

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
#pragma warning restore 612, 618
        }
    }
}