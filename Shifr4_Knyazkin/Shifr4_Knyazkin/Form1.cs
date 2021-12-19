using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Data.Sqlite;

namespace Shifr4_Knyazkin
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {


        }

        private void button1_Click(object sender, EventArgs e)
        {
            textBox3.Text = "";
            dataGridView1.Rows.Clear();
            if (radioButton1.Checked)
            {
                executeUnsafe();
            }
            else if (radioButton2.Checked)
            {
                executeSafe();
            }
            else
            {
                MessageBox.Show("Choose mode");
            }
        }

        private void executeUnsafe()
        {
            string conString = "Data Source=users.db";
            var connection = new SqliteConnection(conString);
            connection.Open();
            string whereCondition1;
            string whereCondition2;
            if (!String.IsNullOrEmpty(textBox1.Text))
            {
                whereCondition1 = @textBox1.Text;
            }
            else return;
            if (!String.IsNullOrEmpty(textBox2.Text))
            {
                whereCondition2 = @textBox2.Text;
            }
            else return;

            string query = @"SELECT * from data WHERE id=" + "'" + @whereCondition1 + "'" + " AND login=" + "'" + @whereCondition2 + "'";
            var command = connection.CreateCommand();
            command.CommandText = query;
            var reader = command.ExecuteReader();
            List<string[]> data = new List<string[]>();
            while (reader.Read())
            {
                data.Add(new string[3]);
                data[data.Count - 1][0] = reader[0].ToString();
                data[data.Count - 1][1] = reader[1].ToString();
                data[data.Count - 1][2] = reader[2].ToString();
            }
            reader.Close();
            connection.Close();
            foreach (string[] str in data)
            {
                dataGridView1.Rows.Add(str);
            }
            textBox3.Text = command.CommandText;
        }
        private void executeSafe()
        {
            string conString = "Data Source=users.db;Mode=ReadOnly;"; // Устанаваливаем права доступа к бд  
            var connection = new SqliteConnection(conString);
            connection.Open();
            string whereCondition1;
            string whereCondition2;
            string query = @"SELECT * FROM data WHERE id = $id AND login = $login";
            var command = connection.CreateCommand();
            command.CommandText = query;
            if (!String.IsNullOrEmpty(textBox1.Text))
            {
                int cond1;
                if (Int32.TryParse(textBox1.Text, out cond1))
                {
                    command.Parameters.AddWithValue("$id", cond1);
                }
                else
                {
                    textBox3.Text = "Invalid input.";
                    return;
                }
            }
            else return;
            if (!String.IsNullOrEmpty(textBox2.Text))
            {
                whereCondition2 = @textBox2.Text;
                command.Parameters.AddWithValue("$login", whereCondition2);
            }
            else return;
            var reader = command.ExecuteReader();
            List<string[]> data = new List<string[]>();
            while (reader.Read())
            {
                data.Add(new string[3]);
                data[data.Count - 1][0] = reader[0].ToString();
                data[data.Count - 1][1] = reader[1].ToString();
                data[data.Count - 1][2] = reader[2].ToString();
            }
            reader.Close();
            connection.Close();
            foreach (string[] str in data)
            {
                dataGridView1.Rows.Add(str);
            }
            textBox3.Text = command.CommandText;
        }


    }
}