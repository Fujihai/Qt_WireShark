#include "mainwindow.h"
#include "ui_mainwindow.h"

#define STR_IP           "Internet Protocol"
#define STR_TCP          "Transmission Control Protocol"
#define STR_UDP          "User Datagram Protocol"
#define STR_ICMP         "Internet Control Message Protocol"
#define STR_IGMP         "Internet Group Management Protocol"
#define STR_PING_REQUEST "Echo (Ping) Request!"
#define STR_PING_REPLY   "Echo (Ping) Reply!"

typedef struct ethhdr  ETH_HEADER;
typedef struct iphdr   IP_HEADER;
typedef struct icmphdr ICMP_HEADER;
typedef struct tcphdr  TCP_HEADER;
typedef struct udphdr  UDP_HEADER;

ETH_HEADER  *ethHdr;
IP_HEADER   *ipHdr;
TCP_HEADER  *tcpHdr;
UDP_HEADER  *udpHdr;
ICMP_HEADER *icmpHdr;

pthread_t cap_thread_id;
int sock, n, num;
unsigned char buffer[1518];	      //临时存储捕获的数据包
unsigned char *iphead, *ethhead;

unsigned char* p_src_ip;
unsigned char* p_dst_ip;
pthread_mutex_t mutex;                //互斥区

int Frame_Counter = 0;                //定义收到的帧的数量
bool thread_exited_flag = false;      //判断线程是否已经退出
bool thread_created_flag = false;

char proto_type_ipHdr;
unsigned short proto_type_ethHdr;

QList<unsigned char *> FrameList;     //定义List
QList<int> FrameLength_List;

int ColumnWidth[7] = {90,150,150,150,150,90,150};

QStandardItemModel *info_tableView_model = new QStandardItemModel();   //数据模型

void capture_pthread();

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->info_tableView,SIGNAL(clicked(QModelIndex)),this,SLOT(on_info_tableView_clicked(QModelIndex)));

    if((sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)  //构造函数中创建一次socket即可
    {
           qDebug()<<"Create Socket failed!";
           //exit(1);
    }

    //设置info_tableView的属性
    {
        info_tableView_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("No.")));
        info_tableView_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source IP")));
        info_tableView_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Destination IP")));
        info_tableView_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Source MAC")));
        info_tableView_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Destination MAC")));
        info_tableView_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Protocol")));
        info_tableView_model->setHorizontalHeaderItem(6, new QStandardItem(QObject::tr("Info")));

        //利用setModel()方法将数据模型与QTableView绑定
        ui->info_tableView->setModel(info_tableView_model);

        //设置列宽
        for(int i = 0; i < 7; i++)
        {
            ui->info_tableView->setColumnWidth(i,ColumnWidth[i]);
        }


        ui->info_tableView->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);

        ui->info_tableView->verticalHeader()->hide();                             //隐藏默认显示的行头
        ui->info_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选中时为整行选中
        ui->info_tableView->setSelectionMode(QAbstractItemView::SingleSelection); //设置只能选中一行
        ui->info_tableView->setTextElideMode(Qt::ElideMiddle);
        ui->info_tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);   //设置表格的单元为只读属性，即不能编辑
        ui->info_tableView->setFixedWidth(90*2+150*5);                            //设置info_tableView的宽度
    }
    ui->stop_pushButton->setEnabled(false);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void capture_pthread()
{
    qDebug("entering capture_thread\n");

       pthread_mutex_init(&mutex,NULL);    //初始化互斥区

       QString src_mac_str = "",dst_mac_str = "",src_ip_str = "",dst_ip_str = "",num_str = "",proto_ipHdr_str = "",info_str = "";

       while(1)
       {
           src_mac_str = "",dst_mac_str = "",src_ip_str = "",dst_ip_str = "",num_str = "",proto_ipHdr_str = "",info_str = "None";

           n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);

           ethhead = buffer;
           ipHdr  = (IP_HEADER *)(buffer+sizeof(ETH_HEADER));   //IP Header
           ethHdr = (ETH_HEADER *)(buffer);                      //Ether Header
           icmpHdr = (ICMP_HEADER *)(buffer+sizeof(ETH_HEADER)+sizeof(IP_HEADER));

           proto_type_ethHdr = htons(ethHdr->h_proto);              //以太网帧头中协议类型的判断
           proto_type_ipHdr = *(ethhead + ETH_HLEN + 9);            //IP报头中协议类型的判断

          // printf("protocol type: 0x%04x\n",htons((ethHdr->type)));
           //printf("protocol type: 0x%04x\n",protocol_type);

           bool is_IP_Proto_Flag = false;
           bool is_Proto_Flag = false;

           switch(proto_type_ethHdr)
           {
               case(0x0800):
                   switch(proto_type_ipHdr)
                   {
                       case 0x01:
                           proto_ipHdr_str = "ICMP";
                           is_IP_Proto_Flag = true;

                           if((icmpHdr->type == ICMP_ECHOREPLY)&&(icmpHdr->code == 0))
                           {
                               info_str = STR_PING_REPLY;
                           }
                           else if((icmpHdr->type == ICMP_ECHO)&&(icmpHdr->code == 0))
                           {
                               info_str = STR_PING_REQUEST;
                           }

                           break;

                       case 0x02:
                           proto_ipHdr_str = "IGMP";
                           is_IP_Proto_Flag = true;
                           break;

                       case 0x06:
                           proto_ipHdr_str = "TCP";
                           is_IP_Proto_Flag = true;
                           break;

                       case 0x11:
                           proto_ipHdr_str = "UDP";
                           is_IP_Proto_Flag = true;
                           break;

                       default:
                           break;
                   }
                   is_Proto_Flag = true;
                   break;

               case(0x0806):  //ARP
                   //proto_ipHdr_str = "ARP";
                   //is_Proto_Flag = 1;
                   break;

               case(0x8035):  //RARP
                   //proto_ipHdr_str = "RARP";
                   //is_Proto_Flag = 1;
                   break;

               default:
                   break;
           }

           if(1 == is_Proto_Flag)
           {
               unsigned char *p_buff = NULL;
               p_src_ip = (unsigned char*)&ipHdr->saddr;
               p_dst_ip = (unsigned char*)&ipHdr->daddr;

               p_buff = (unsigned char *) malloc(n);
               memcpy(p_buff,buffer,n);
               FrameList.append(p_buff);
               FrameLength_List.append(n);

               num_str.sprintf("%d",Frame_Counter);
               dst_mac_str.sprintf("%02x:%02x:%02x:%02x:%02x:%02x",ethhead[0],ethhead[1],ethhead[2],ethhead[3],ethhead[4],ethhead[5]);
               src_mac_str.sprintf("%02x:%02x:%02x:%02x:%02x:%02x",ethhead[6],ethhead[7],ethhead[8],ethhead[9],ethhead[10],ethhead[11]);
               src_ip_str.sprintf("%u.%u.%u.%u",p_src_ip[0],p_src_ip[1],p_src_ip[2],p_src_ip[3]);
               dst_ip_str.sprintf("%u.%u.%u.%u",p_dst_ip[0],p_dst_ip[1],p_dst_ip[2],p_dst_ip[3]);

               //setItem函数的第一个参数表示行号，第二个表示列号，第三个为要显示的数据
               info_tableView_model->setItem(Frame_Counter, 0, new QStandardItem(num_str));
               info_tableView_model->setItem(Frame_Counter, 1, new QStandardItem(src_ip_str));
               info_tableView_model->setItem(Frame_Counter, 2, new QStandardItem(dst_ip_str));
               info_tableView_model->setItem(Frame_Counter, 3, new QStandardItem(src_mac_str));
               info_tableView_model->setItem(Frame_Counter, 4, new QStandardItem(dst_mac_str));
               info_tableView_model->setItem(Frame_Counter, 5, new QStandardItem(proto_ipHdr_str));
               info_tableView_model->setItem(Frame_Counter, 6, new QStandardItem(info_str));

               //设置单元格文本居中，数据设置为居中显示
               for(int i=0; i<7; i++)
               {
                   info_tableView_model->item(Frame_Counter, i)->setTextAlignment(Qt::AlignCenter);
               }

               Frame_Counter ++;
           }
           memset(buffer,0,sizeof(buffer));

           pthread_mutex_lock(&mutex);
           if(true == thread_exited_flag)         //判断线程是否需要退出
           {
               int retvalue = 8;
               thread_exited_flag = false;
               //qDebug("(Capture Thread)thread_exited_flag = %d \n",thread_exited_flag);
               qDebug("leaving capture_thread\n");
               pthread_exit((void*)&retvalue);
           }
           pthread_mutex_unlock(&mutex);
       }
}

void MainWindow::on_start_pushButton_clicked()
{
    qDebug()<<"Start Btn Press!";


    int ret;

       qDebug("entering main thread\n");

       /*创建线程capture_pthread*/

       if(thread_created_flag == false)
       {
           thread_created_flag = true;

           ret = pthread_create(&cap_thread_id,NULL,(void*(*)(void*))capture_pthread, NULL);
           if(ret != 0) {
                   perror("capture_pthread create");
           }

           ui->stop_pushButton->setEnabled(true);
           ui->start_pushButton->setEnabled(false);
       }

}

void MainWindow::on_stop_pushButton_clicked()
{
     if(thread_created_flag == true)
         {
             pthread_mutex_lock(&mutex);
             if(thread_exited_flag == false)
             {
                 thread_exited_flag = true;
             }
             qDebug("(stop button)thread_exited_flag = %d \n",thread_exited_flag);
             pthread_mutex_unlock(&mutex);

             thread_created_flag = false;
             ui->start_pushButton->setEnabled(true);
             ui->stop_pushButton->setEnabled(false);
         }
}

void MainWindow::on_info_tableView_clicked(const QModelIndex &index)
{
        int     selected_row = 0;
        int     frame_length = 0;
        char    frame_protocol_type;

        QList <QString> info_frame_bytes_List;
        QList <QString> info_frame_Eth_Hdr_List;
        QList <QString> info_frame_Ip_Hdr_List;
        QList <QString> info_frame_Trans_Layer_List;

        QString frame_proto_ipHdr_str = "";
        QString info_frame_bytes = "";
        QString info_frame_bytes_child = "";
        QString info_frame_brief_protocol = "";

        QString info_frame_Eth_Hdr = "";
        QString info_frame_Eth_Hdr_child = "";

        QString info_frame_Ip_Hdr = "";
        QString info_frame_Ip_Hdr_child = "";
        QString info_frame_ip_brief_protocol = "";

        QString info_transport_Layer = "";
        QString info_transport_Layer_child = "";

        selected_row = ui->info_tableView->currentIndex().row();
        frame_length = FrameLength_List[selected_row];

        ethhead = FrameList[selected_row];
        ethHdr= (ETH_HEADER *)(FrameList[selected_row]);
        ipHdr = (IP_HEADER *)(FrameList[selected_row]+sizeof(ETH_HEADER));

        //protocol = *(ethhead + 14 + 9);
        frame_protocol_type = *(ethhead + ETH_HLEN + 9);
        proto_type_ethHdr = htons(ethHdr->h_proto);

        p_src_ip = (unsigned char*)&ipHdr->saddr;
        p_dst_ip = (unsigned char*)&ipHdr->daddr;

        switch(frame_protocol_type)
        {
            case 0x01:
                frame_proto_ipHdr_str = STR_ICMP;
                info_frame_brief_protocol = "icmp";
                info_frame_ip_brief_protocol = "ICMP";

                icmpHdr = (ICMP_HEADER *)(FrameList[selected_row]+sizeof(ETH_HEADER)+sizeof(IP_HEADER));

                info_transport_Layer_child.sprintf("Type: %d",icmpHdr->type);                         info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Code: %d",icmpHdr->code);                         info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Checksum: 0x%04x",htons(icmpHdr->checksum));      info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                //info_transport_Layer_child.sprintf("Identifier: 0x%04x",htons(icmpHdr->un->id));                   info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                //info_transport_Layer_child.sprintf("Sequence Number: 0x%04x",htons(icmpHdr->un->sequence));    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                break;

            case 0x02:
                frame_proto_ipHdr_str = STR_IGMP;
                info_frame_brief_protocol = "igmp";
                info_frame_ip_brief_protocol = "IGMP";
                break;

            case 0x06:
                frame_proto_ipHdr_str = STR_TCP;
                info_frame_brief_protocol = "tcp";
                info_frame_ip_brief_protocol = "TCP";

                //tcpHdr= (TCP_HEADER *)(ipHdr + ipHdr->ihl*4);
                tcpHdr= (TCP_HEADER *)(FrameList[selected_row]+sizeof(ETH_HEADER)+sizeof(IP_HEADER));

                info_transport_Layer_child.sprintf("Src Port: %d",htons(tcpHdr->source));                 info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Dest Port: %d",htons(tcpHdr->dest));                  info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Sequence Number: %d",htonl(tcpHdr->seq));             info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Acknowledgment Number: %d", htonl(tcpHdr->ack_seq));  info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                break;

            case 0x11:
                frame_proto_ipHdr_str = STR_UDP;
                info_frame_brief_protocol = "udp";
                info_frame_ip_brief_protocol = "UDP";

                //udpHdr = (UDP_HEADER *)(ipHdr + ipHdr->ihl*4);
                udpHdr = (UDP_HEADER *)(FrameList[selected_row]+sizeof(ETH_HEADER)+sizeof(IP_HEADER));

                info_transport_Layer_child.sprintf("Src Port: %d",htons(udpHdr->source));     info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Dest Port: %d",htons(udpHdr->dest));      info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Length: %d",htons(udpHdr->len));          info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                info_transport_Layer_child.sprintf("Checksum: 0x%04x", htons(udpHdr->check));    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                break;

            default:
                break;
        }

        info_frame_bytes.sprintf("Frame %d (%d bytes on wire, %d bytes on captured)",
                                 selected_row, frame_length, frame_length);


        info_frame_bytes_child.sprintf("Frame Number: %d",selected_row);  info_frame_bytes_List.append(info_frame_bytes_child);
        info_frame_bytes_child.sprintf("Packet Length: %d bytes",frame_length);   info_frame_bytes_List.append(info_frame_bytes_child);
        info_frame_bytes_child.sprintf("Capture Length: %d bytes",frame_length);  info_frame_bytes_List.append(info_frame_bytes_child);
        //info_frame_bytes_child.sprintf("[Protocols in frame: eth:ip:"+ info_frame_brief_protocol + "]");  info_frame_bytes_List.append(info_frame_bytes_child); //Debianx Qt4 Usage
        info_frame_bytes_child = QString("%1%2%3").arg("[Protocols in frame: eth:ip:").arg(info_frame_brief_protocol).arg("]"); info_frame_bytes_List.append(info_frame_bytes_child);

        info_frame_Eth_Hdr.sprintf("Ethernet II, Src: %02x:%02x:%02x:%02x:%02x:%02x, Dst: %02x:%02x:%02x:%02x:%02x:%02x",
                                   ethhead[6],ethhead[7],ethhead[8],
                                   ethhead[9],ethhead[10],ethhead[11],
                                   ethhead[0],ethhead[1],ethhead[2],
                                   ethhead[3],ethhead[4],ethhead[5]
                                   );

        info_frame_Eth_Hdr_child.sprintf("Destionation: %02x:%02x:%02x:%02x:%02x:%02x (%02x:%02x:%02x:%02x:%02x:%02x)",
                                         ethhead[0],ethhead[1],ethhead[2],
                                         ethhead[3],ethhead[4],ethhead[5],
                                         ethhead[0],ethhead[1],ethhead[2],
                                         ethhead[3],ethhead[4],ethhead[5]);
        info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);

        info_frame_Eth_Hdr_child.sprintf("Source: %02x:%02x:%02x:%02x:%02x:%02x (%02x:%02x:%02x:%02x:%02x:%02x)",
                                         ethhead[6],ethhead[7],ethhead[8],
                                         ethhead[9],ethhead[10],ethhead[11],
                                         ethhead[6],ethhead[7],ethhead[8],
                                         ethhead[9],ethhead[10],ethhead[11]);
        info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);

        info_frame_Eth_Hdr_child.sprintf("Type: 0x%04x (IP)",proto_type_ethHdr);
        info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);


        info_frame_Ip_Hdr.sprintf("Internet Protocol, Src: %u.%u.%u.%u, Dst: %u.%u.%u.%u",
                                   p_src_ip[0],p_src_ip[1],p_src_ip[2],p_src_ip[3],
                                   p_dst_ip[0],p_dst_ip[1],p_dst_ip[2],p_dst_ip[3]
                                   );

        info_frame_Ip_Hdr_child.sprintf("Version: 4 ");                                                               info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Total Length: %d", htons(ipHdr->tot_len));                                   info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Identification: 0x%04x (%d)", htons(ipHdr->id), htons(ipHdr->id));           info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Fragment Offset: %d", htons(ipHdr->frag_off));                               info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Time to Live: %d", htons(ipHdr->ttl));                                       info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        //info_frame_Ip_Hdr_child.sprintf("Protocol:0x%02x (" +info_frame_ip_brief_protocol + ")", ipHdr->protocol);
        info_frame_Ip_Hdr_child = QString("Protocol: %1 (%2)").arg(info_frame_ip_brief_protocol).arg(ipHdr->protocol);
        info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Header Checksum: 0x%04x",  htons(ipHdr->check));                             info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Source: %u.%u.%u.%u", p_src_ip[0],p_src_ip[1],p_src_ip[2],p_src_ip[3]);     info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
        info_frame_Ip_Hdr_child.sprintf("Destionation: %u.%u.%u.%u ", p_dst_ip[0],p_dst_ip[1],p_dst_ip[2],p_dst_ip[3]); info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);

        //info_transport_Layer.sprintf(frame_proto_ipHdr_str);
        info_transport_Layer = QString("%1").arg(frame_proto_ipHdr_str);

        ui->treeWidget->setColumnCount(1); //设置列数
        ui->treeWidget->clear();

        //Info_treeWidget节点添加
        {
            QTreeWidgetItem *Item1 = new QTreeWidgetItem(ui->treeWidget,QStringList(info_frame_bytes));
            for(int i = 0; i < info_frame_bytes_List.count(); i++)
            {
                QTreeWidgetItem *Item1_1 = new QTreeWidgetItem(Item1,QStringList(info_frame_bytes_List[i])); //子节点1_1
                Item1->addChild(Item1_1); //添加子节点
            }

            QTreeWidgetItem *Item2 = new QTreeWidgetItem(ui->treeWidget,QStringList(info_frame_Eth_Hdr));
            for(int i = 0; i < info_frame_Eth_Hdr_List.count(); i++)
            {
                QTreeWidgetItem *Item2_1 = new QTreeWidgetItem(Item2,QStringList(info_frame_Eth_Hdr_List[i])); //子节点1_1
                Item2->addChild(Item2_1); //添加子节点
            }

            QTreeWidgetItem *Item3 = new QTreeWidgetItem(ui->treeWidget,QStringList(info_frame_Ip_Hdr));
            for(int i = 0; i < info_frame_Ip_Hdr_List.count(); i++)
            {
                QTreeWidgetItem *Item3_1 = new QTreeWidgetItem(Item3,QStringList(info_frame_Ip_Hdr_List[i])); //子节点1_1
                Item3->addChild(Item3_1); //添加子节点
            }

            QTreeWidgetItem *Item4 = new QTreeWidgetItem(ui->treeWidget,QStringList(info_transport_Layer));
            for(int i = 0; i < info_frame_Trans_Layer_List.count(); i++)
            {
                QTreeWidgetItem *Item4_1 = new QTreeWidgetItem(Item4,QStringList(info_frame_Trans_Layer_List[i])); //子节点1_1
                Item4->addChild(Item4_1); //添加子节点
            }
        }
}
