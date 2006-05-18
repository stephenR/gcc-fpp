/* GtkWindowPeer.java -- Implements WindowPeer with GTK
   Copyright (C) 1998, 1999, 2002, 2005, 2006  Free Software Foundation, Inc.

This file is part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version. */


package gnu.java.awt.peer.gtk;

import java.awt.AWTEvent;
import java.awt.Component;
import java.awt.Frame;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.ComponentEvent;
import java.awt.event.PaintEvent;
import java.awt.event.WindowEvent;
import java.awt.peer.WindowPeer;

public class GtkWindowPeer extends GtkContainerPeer
  implements WindowPeer
{
  protected static final int GDK_WINDOW_TYPE_HINT_NORMAL = 0;
  protected static final int GDK_WINDOW_TYPE_HINT_DIALOG = 1;
  protected static final int GDK_WINDOW_TYPE_HINT_MENU = 2;
  protected static final int GDK_WINDOW_TYPE_HINT_TOOLBAR = 3;
  protected static final int GDK_WINDOW_TYPE_HINT_SPLASHSCREEN = 4;
  protected static final int GDK_WINDOW_TYPE_HINT_UTILITY = 5;
  protected static final int GDK_WINDOW_TYPE_HINT_DOCK = 6;
  protected static final int GDK_WINDOW_TYPE_HINT_DESKTOP = 7;

  private boolean hasBeenShown = false;
  private int oldState = Frame.NORMAL;

  // Cached awt window component location, width and height.
  private int x, y, width, height;

  native void gtkWindowSetTitle (String title);
  native void gtkWindowSetResizable (boolean resizable);
  native void gtkWindowSetModal (boolean modal);

  native void realize ();

  /** Returns the cached width of the AWT window component. */
  int getX ()
  {
    return x;
  }

  /** Returns the cached width of the AWT window component. */
  int getY ()
  {
    return y;
  }

  /** Returns the cached width of the AWT window component. */
  int getWidth ()
  {
    return width;
  }

  /** Returns the cached height of the AWT window component. */
  int getHeight ()
  {
    return height;
  }

  native void create (int type, boolean decorated, GtkWindowPeer parent);

  void create (int type, boolean decorated)
  {
    Window window = (Window) awtComponent;
    GtkWindowPeer parent_peer = null;
    Component parent = awtComponent.getParent();
    x = awtComponent.getX();
    y = awtComponent.getY();
    height = awtComponent.getHeight();
    width = awtComponent.getWidth();
    
    if (!window.isFocusableWindow())
      type = GDK_WINDOW_TYPE_HINT_MENU;
    
    if (parent != null)
      parent_peer = (GtkWindowPeer) awtComponent.getParent().getPeer();
    
    create (type, decorated, parent_peer);
  }

  void create ()
  {
    // Create a normal undecorated window.
    create (GDK_WINDOW_TYPE_HINT_NORMAL, false);
  }

  void setParent ()
  {
    setVisible (awtComponent.isVisible ());
    setEnabled (awtComponent.isEnabled ());
  }

  void setVisibleAndEnabled ()
  {
  }

  public native void setVisibleNative (boolean b);
  public native void setVisibleNativeUnlocked (boolean b);

  native void connectSignals ();

  public GtkWindowPeer (Window window)
  {
    super (window);
  }

  public native void toBack();
  public native void toFront();

  native void nativeSetBounds (int x, int y, int width, int height);
  native void nativeSetBoundsUnlocked (int x, int y, int width, int height);
  native void nativeSetLocation (int x, int y);
  native void nativeSetLocationUnlocked (int x, int y);

  // Called from show.
  protected void setLocation (int x, int y)
  {
    nativeSetLocation (x, y);
  }

  public void setBounds (int x, int y, int width, int height)
  {
    if (x != getX()
	|| y != getY()
	|| width != getWidth()
	|| height != getHeight())
      {
	this.x = x;
	this.y = y;
	this.width = width;
	this.height = height;
	
	nativeSetBounds (x, y,
			 width - insets.left - insets.right,
			 height - insets.top - insets.bottom);
      }
  }

  public void setTitle (String title)
  {
    gtkWindowSetTitle (title);
  }

  // Called from setResizable
  protected native void setSize (int width, int height);
  
  /**
   * Needed by both GtkFramePeer and GtkDialogPeer subclasses, so
   * implemented here. But never actually called on a GtkWindowPeer
   * itself.
   */
  public void setResizable (boolean resizable)
  {
    // Call setSize; otherwise when resizable is changed from true to
    // false the window will shrink to the dimensions it had before it
    // was resizable.
    x = awtComponent.getX();
    y = awtComponent.getY();
    width = awtComponent.getWidth();
    height = awtComponent.getHeight();
    setSize (width - insets.left - insets.right,
	     height - insets.top - insets.bottom);
    gtkWindowSetResizable (resizable);
  }

  protected void postInsetsChangedEvent (int top, int left,
					 int bottom, int right)
  {
    insets.top = top;
    insets.left = left;
    insets.bottom = bottom;
    insets.right = right;
  }

  // called back by native side: window_configure_cb
  // only called from GTK thread
  protected void postConfigureEvent (int x, int y, int width, int height)
  {
    int frame_width = width + insets.left + insets.right;
    int frame_height = height + insets.top + insets.bottom;

    if (frame_width != getWidth()
	|| frame_height != getHeight())
      {
	this.width = frame_width;
	this.height = frame_height;
	q().postEvent(new ComponentEvent(awtComponent,
					 ComponentEvent.COMPONENT_RESIZED));
      }

    int frame_x = x - insets.left;
    int frame_y = y - insets.top;

    if (frame_x != getX()
	|| frame_y != getY())
      {
	this.x = frame_x;
	this.y = frame_y;
	q().postEvent(new ComponentEvent(awtComponent,
					 ComponentEvent.COMPONENT_MOVED));
      }
  }

  public void show ()
  {
    x = awtComponent.getX();
    y = awtComponent.getY();
    width = awtComponent.getWidth();
    height = awtComponent.getHeight();
    setLocation(x, y);
    setVisible (true);
  }

  void postWindowEvent (int id, Window opposite, int newState)
  {
    if (id == WindowEvent.WINDOW_OPENED)
      {
	// Post a WINDOW_OPENED event the first time this window is shown.
	if (!hasBeenShown)
	  {
	    q().postEvent (new WindowEvent ((Window) awtComponent, id,
					  opposite));
	    hasBeenShown = true;
	  }
      }
    else if (id == WindowEvent.WINDOW_STATE_CHANGED)
      {
	if (oldState != newState)
	  {
	    q().postEvent (new WindowEvent ((Window) awtComponent, id, opposite,
					  oldState, newState));
	    oldState = newState;
	  }
      }
    else
      q().postEvent (new WindowEvent ((Window) awtComponent, id, opposite));
  }
  public void updateAlwaysOnTop()
  {
    // TODO Auto-generated method stub
    
  }

  protected void postExposeEvent (int x, int y, int width, int height)
  {
    // Translate GTK co-ordinates, which do not include a window
    // frame's insets, to AWT co-ordinates, which do include a window
    // frame's insets.  GtkWindowPeer should always have all-zero
    // insets but GtkFramePeer and GtkDialogPeer insets will be
    // non-zero.
    q().postEvent (new PaintEvent (awtComponent, PaintEvent.PAINT,
                                   new Rectangle (x + insets.left, 
                                                  y + insets.top, 
                                                  width, height)));
  }

  public boolean requestWindowFocus()
  {
    // TODO Auto-generated method stub
    return false;
  }
  
  public Graphics getGraphics ()
  {
    Graphics g = super.getGraphics ();
    // Translate AWT co-ordinates, which include a window frame's
    // insets, to GTK co-ordinates, which do not include a window
    // frame's insets.  GtkWindowPeer should always have all-zero
    // insets but GtkFramePeer and GtkDialogPeer insets will be
    // non-zero.
    g.translate (-insets.left, -insets.top);
    return g;
  }

  protected void updateComponent (PaintEvent event)
  {
    // Do not clear anything before painting.  Sun never calls
    // Window.update, only Window.paint.
    paintComponent(event);
  }

  protected void postMouseEvent(int id, long when, int mods, int x, int y, 
				int clickCount, boolean popupTrigger)
  {
    // Translate AWT co-ordinates, which include a window frame's
    // insets, to GTK co-ordinates, which do not include a window
    // frame's insets.  GtkWindowPeer should always have all-zero
    // insets but GtkFramePeer and GtkDialogPeer insets will be
    // non-zero.
    super.postMouseEvent (id, when, mods, 
			  x + insets.left, y + insets.top, 
			  clickCount, popupTrigger);
  }

  // We override this to keep it in sync with our internal
  // representation.
  public Rectangle getBounds()
  {
    return new Rectangle(x, y, width, height);
  }
}
