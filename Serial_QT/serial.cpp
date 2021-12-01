#include "serial.h"
#include "ui_serial.h"

Serial::Serial(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::Serial)
{
  ui->setupUi(this);
  //user
  system_init();
}

Serial::~Serial()
{
  delete ui;
}
/******************************
 *           FUNTIONS
 *****************************/
void Serial::system_init()
 {
   global_port.setParity(QSerialPort::NoParity);
   global_port.setDataBits(QSerialPort::Data8);
   global_port.setStopBits(QSerialPort::OneStop);
   connect(ui->btn_open,&QPushButton::clicked,this,&Serial::btn_open_port);
   connect(ui->btn_send,&QPushButton::clicked,this,&Serial::btn_send_data);
   connect(&global_port,&QSerialPort::readyRead,this,&receive_data);
   connect(ui->btn_close,&QPushButton::clicked,this,&Serial::btn_set_close);
  }
/******************************
 *           SLOTS
 * ****************************/
void Serial::btn_open_port(bool)
{
/***************PORT NAME****************/
//  qDebug()<<ui->cmb_port_name->currentIndex();
  switch (ui->cmb_port_name->currentIndex()) {
    case 0:
  global_port.setPortName("COM1");
      break;
    case 1:
  global_port.setPortName("COM2");
      break;
    case 2:
  global_port.setPortName("COM3");
      break;
    case 3:
  global_port.setPortName("COM4");
      break;
    case 4:
  global_port.setPortName("COM5");
      break;
    case 5:
  global_port.setPortName("COM6");
      break;
    case 6:
  global_port.setPortName("COM7");
      break;
    default:
         global_port.setPortName("COM8");
      break;
    }
/***************BOUD RATE********************/
  global_port.setBaudRate(QSerialPort::Baud115200);
  global_port.open(QIODevice::ReadWrite);
//  //TEST
//  global_port.write("1");
  ui->label_1->setText("connected");

    }
/********************send data***********************************/
void Serial::btn_send_data(bool)
{
  QString data = ui->lint_send_data->text();
  QByteArray array = data.toLatin1();
  global_port.write(array);
}

/********************receive data**********************************/
double dataDouble[27];
int dataInt[3];
void Serial::receive_data()
{
    //QByteArray readLine(qint64 maxlen = 0);
  QByteArray array = global_port.readLine();

  char* ch = array.data();
  if(array.size() == 467) {
      ch += 8;
      //在串口上 ASCII码[a-p] 用来表示4个bit, 我们4bit,4bit地进行传输
      int node_num = (*ch++) - 'a';

      int64_t* doubleptr = reinterpret_cast<int64_t *>(dataDouble);
      for(int j = 0; j < 27; ++j) {
          int64_t a;
          for(int i = 0; i < 16; ++i) {
            a <<= 4;
            a |= (*ch++) - 'a';

          }
          *doubleptr++ = a;
      }

      int32_t* intptr = reinterpret_cast<int32_t *>(dataInt);
      for(int j = 0; j < 3; ++j) {
          int32_t b;
          for(int i = 0; i < 8; ++i) {
            b <<= 4;
            b |= (*ch++) - 'a';

          }
          *intptr++ = b;
      }
      print_data(node_num, dataDouble, dataInt);
  }
}

void Serial::print_data(int node_num, double data1[], int data2[]) {

    QString str =  "received data, node numer =  " + QString::number(node_num) + ": ";
    for(int i = 0; i < 27; ++i) {
        str += QString::number(data1[i]) + ", ";
    }
    for(int i = 0; i < 3; ++i) {
        str += QString::number(data2[i]) + ", ";
    }
    str += "\n";
    ui->plainTextEdit->insertPlainText(str);
}

/*******************CLOSE************************************/
void Serial::btn_set_close(bool)
{
  global_port.close();
  ui->label_1->setText("Disconnected");
}
