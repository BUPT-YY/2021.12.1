#ifndef SERIAL_H
#define SERIAL_H

#include <QMainWindow>
#include <QtSerialPort/QSerialPort>
//debug
#include <QDebug>

namespace Ui {
  class Serial;
}

class Serial : public QMainWindow
{
  Q_OBJECT

public:
  explicit Serial(QWidget *parent = 0);
  ~Serial();

private slots:
  //BUTTON
  void btn_open_port(bool);
  void btn_send_data(bool);
  void btn_set_close(bool);

  //RECEIVE_DATA
  void receive_data();
  void print_data(int node_num, double data1[], int data2[]);


private:
  Ui::Serial *ui;
  /************FUNTION***************/
  void system_init();
  /************VARIABLE***************/
  QSerialPort global_port;
};


#endif // SERIAL_H
