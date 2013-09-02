/* X-Chat
 * Copyright (C) 1998 Peter Zelezny.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fe-gtk.h"
#include <gtk/gtk.h>
#include "../common/hexchat.h"
#include "../common/util.h"
#include "palette.h"
#include "pixmaps.h"
#include "gtkutil.h"

static GtkWidget *sslalert = 0;
static GtkWidget *sslalert_savecheck = 0;

void (*sslalert_cb)(int, void *) = 0;
void *sslalert_cb_data = 0;

static void
sslalert_user_accept (GtkWidget * wid)
{
	if (sslalert)
	{
		int save_setting = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sslalert_savecheck));
		GtkWidget *tmp = sslalert;
		sslalert = 0;
		gtk_widget_destroy (tmp);
		/* save certificate and continue, or just accept this once? */
		sslalert_cb ((save_setting?2:1), sslalert_cb_data);
	}
}

static void
sslalert_user_reject ()
{
	if (sslalert)
	{
		GtkWidget *tmp = sslalert;
		sslalert = 0;
		gtk_widget_destroy (tmp);
		sslalert_cb (0, sslalert_cb_data);
	}
}

void
fe_sslalert_open (struct server *serv, void (*callback)(int, void *), void *callback_data)
{
	GtkWidget *wid;
	GtkWidget *dialog_vbox;
	GtkWidget *hbox1, *vbox1, *vbox2;
	GtkWidget *img_vbox;
	char buf[256];
	char buf2[256];

	sslalert_cb = callback;
	sslalert_cb_data = callback_data;

	if (sslalert)
		return;

	sslalert = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (sslalert), _(DISPLAY_NAME": Security Alert"));
	gtk_window_set_type_hint (GTK_WINDOW (sslalert), GDK_WINDOW_TYPE_HINT_DIALOG);
	gtk_window_set_position (GTK_WINDOW (sslalert), GTK_WIN_POS_CENTER);
	gtk_window_set_resizable (GTK_WINDOW (sslalert), FALSE);

	g_signal_connect (G_OBJECT (sslalert), "destroy", G_CALLBACK (sslalert_user_reject), 0);

	dialog_vbox = GTK_DIALOG (sslalert)->vbox;

	vbox1 = gtk_vbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (dialog_vbox), vbox1, TRUE, TRUE, 0);

	hbox1 = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox1), hbox1, TRUE, TRUE, 0);

	img_vbox = gtk_vbox_new (FALSE, 10);
	gtk_container_set_border_width (GTK_CONTAINER (img_vbox), 6);
	gtk_box_pack_start (GTK_BOX (hbox1), img_vbox, TRUE, TRUE, 0);

	wid = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_box_pack_start (GTK_BOX (img_vbox), wid, FALSE, TRUE, 24);
	gtk_misc_set_alignment (GTK_MISC (wid), 0.5, 0.06);

	vbox2 = gtk_vbox_new (FALSE, 10);
	gtk_container_set_border_width (GTK_CONTAINER (vbox2), 6);
	gtk_box_pack_start (GTK_BOX (hbox1), vbox2, TRUE, TRUE, 0);

	snprintf (buf2, sizeof (buf2), _("Connecting to %s (+%d)"),
	serv->hostname, serv->port);
	snprintf (buf, sizeof (buf), "\n<b>%s</b>", buf2);
	wid = gtk_label_new (buf);
	gtk_box_pack_start (GTK_BOX (vbox2), wid, FALSE, FALSE, 0);
	gtk_label_set_use_markup (GTK_LABEL (wid), TRUE);
	gtk_misc_set_alignment (GTK_MISC (wid), 0, 0.5);

	wid = gtk_label_new (_("This server has presented an invalid certificate, and is self-signed, expired, or has another problem."));
	gtk_box_pack_start (GTK_BOX (vbox2), wid, FALSE, FALSE, 0);
	GTK_LABEL (wid)->wrap = TRUE;
	gtk_misc_set_alignment (GTK_MISC (wid), 0, 0.5);

	wid = gtk_label_new (_("If you are certain that your connection is not being tampered with, you can continue and your connection will be secure."));
	gtk_box_pack_start (GTK_BOX (vbox2), wid, FALSE, FALSE, 0);
	GTK_LABEL (wid)->wrap = TRUE;
	gtk_misc_set_alignment (GTK_MISC (wid), 0, 0.5);

	sslalert_savecheck = gtk_check_button_new_with_label(_("Trust this connection in future"));
	gtk_box_pack_start (GTK_BOX (vbox2), sslalert_savecheck, FALSE, FALSE, 0);

	wid = gtkutil_button (GTK_DIALOG (sslalert)->action_area, GTK_STOCK_CANCEL, 0, 0, 0, _("Abort"));
	g_signal_connect (G_OBJECT (wid), "clicked", G_CALLBACK (gtkutil_destroy), sslalert);
	gtk_widget_grab_focus (wid);
	wid = gtkutil_button (GTK_DIALOG (sslalert)->action_area, GTK_STOCK_APPLY, 0, sslalert_user_accept, 0, _("Continue"));

	gtk_widget_show_all (sslalert);
}